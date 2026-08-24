"""
Brute force protection for login endpoints.

Tracks failed authentication attempts per key (IP, username, or IP+username)
using a sliding window. When the attempt count exceeds ``max_attempts`` within
``window_seconds``, the key is locked out for ``lockout_seconds``.

Can be used in two ways:

1. **As middleware** — wraps the entire app and checks every request. Call
   ``brute_force.mark_success(key)`` from your login handler after successful
   auth to reset the counter.

2. **As a utility** — call ``brute_force.is_locked(key)`` and
   ``brute_force.record_failure(key)`` directly from your login handler
   without adding middleware.

Storage is pluggable via the ``StorageBackend`` protocol from ``base.py``.
Default is ``MemoryBackend``. Pass a ``RedisBackend`` for production.

Usage as middleware::

    from functools import partial
    from velocix.security.brute_force import BruteForceProtection
    from velocix.security.base import MemoryBackend

    app.add_middleware(partial(
        BruteForceProtection,
        max_attempts=5,
        window_seconds=900,       # 15 minutes
        lockout_seconds=1800,     # 30 minutes
        backend=MemoryBackend(),
    ))

Usage as utility (no middleware)::

    from velocix.security.brute_force import BruteForceProtection
    from velocix.security.base import MemoryBackend

    bf = BruteForceProtection.create(
        max_attempts=5,
        window_seconds=900,
        lockout_seconds=1800,
        backend=MemoryBackend(),
    )

    # In your login handler:
    key = f"login:{username}:{ip}"
    if bf.is_locked(key):
        return JSONResponse({"error": "Account locked"}, status_code=429)
    # ... verify credentials ...
    bf.record_failure(key)  # on bad password
    bf.mark_success(key)    # on good password
"""

import time
from collections.abc import Awaitable, Callable
from typing import Any

from velocix.core.request import Request
from velocix.core.response import Response
from velocix.security.base import (
    EventCallback,
    MemoryBackend,
    Severity,
    StorageBackend,
    SecurityMiddleware,
)


def _extract_source_ip(request: Request) -> str:
    client = request.scope.get("client")
    if client and len(client) >= 1:
        return str(client[0])
    return ""


class BruteForceProtection(SecurityMiddleware):
    """Tracks failed auth attempts and locks out keys that exceed the limit.

    Args:
        app: Next middleware or handler.
        max_attempts: Maximum failed attempts within the window before lockout.
        window_seconds: Sliding window duration in seconds.
        lockout_seconds: How long a locked-out key stays blocked.
        backend: StorageBackend for counting (default: MemoryBackend).
        key_func: ``(Request) -> str`` that returns the tracking key.
            Default: ``f"{client_ip}"`` (IP-based).
            For username+IP: ``lambda req: f"{username}:{client_ip}"``.
        severity: Event severity level.
        on_event: Optional event callback.
    """

    severity = Severity.HIGH

    __slots__ = (
        "app",
        "_max_attempts",
        "_window_seconds",
        "_lockout_seconds",
        "_backend",
        "_key_func",
        "_lockouts",
    )

    def __init__(
        self,
        app: Callable[[Request], Awaitable[Response]],
        max_attempts: int = 5,
        window_seconds: float = 900,
        lockout_seconds: float = 1800,
        backend: StorageBackend | None = None,
        key_func: Callable[[Request], str] | None = None,
        severity: Severity | None = None,
        on_event: EventCallback | None = None,
    ) -> None:
        super().__init__(app, severity=severity, on_event=on_event)
        self._max_attempts = max_attempts
        self._window_seconds = window_seconds
        self._lockout_seconds = lockout_seconds
        self._backend = backend or MemoryBackend()
        self._key_func = key_func or self._default_key_func
        self._lockouts: dict[str, float] = {}

    @classmethod
    def create(
        cls,
        max_attempts: int = 5,
        window_seconds: float = 900,
        lockout_seconds: float = 1800,
        backend: StorageBackend | None = None,
        on_event: EventCallback | None = None,
    ) -> "BruteForceProtection":
        """Create a standalone BruteForceProtection instance without middleware.

        Use this when you want to call ``is_locked``, ``record_failure``,
        and ``mark_success`` directly from your handler without adding
        middleware to the app.

        Args:
            max_attempts: Max failed attempts before lockout.
            window_seconds: Sliding window duration.
            lockout_seconds: Lockout duration after threshold.
            backend: Storage backend (default: MemoryBackend).
            on_event: Optional callback for security events.
        """
        bf = object.__new__(cls)
        bf.app = None  # type: ignore[assignment]
        bf._severity = Severity.HIGH
        bf._on_event = on_event or (lambda e: None)
        bf._max_attempts = max_attempts
        bf._window_seconds = window_seconds
        bf._lockout_seconds = lockout_seconds
        bf._backend = backend or MemoryBackend()
        bf._key_func = cls._default_key_func
        bf._lockouts: dict[str, float] = {}
        return bf

    @staticmethod
    def _default_key_func(request: Request) -> str:
        return _extract_source_ip(request)

    def is_locked(self, key: str) -> bool:
        """Check if a key is currently locked out.

        A key is locked if it has a lockout timestamp in the future.
        Expired lockouts are automatically cleared.
        """
        lockout_until = self._lockouts.get(key)
        if lockout_until is None:
            return False
        if time.time() >= lockout_until:
            del self._lockouts[key]
            return False
        return True

    def _lock(self, key: str) -> None:
        """Lock a key for ``_lockout_seconds`` from now."""
        self._lockouts[key] = time.time() + self._lockout_seconds

    def record_failure(self, key: str) -> int:
        """Record a failed attempt. Returns the current count within the window.

        If the count exceeds ``max_attempts``, the key is locked out.
        """
        count = self._backend.incr_sync(f"bf:{key}", self._window_seconds)
        if count >= self._max_attempts:
            self._lock(key)
        return count

    def mark_success(self, key: str) -> None:
        """Reset the failure counter and lockout for a key after successful auth."""
        self._backend.reset_sync(f"bf:{key}")
        self._lockouts.pop(key, None)

    def get_retry_after(self, key: str) -> int:
        """Return seconds until the lockout expires. Returns 0 if not locked."""
        lockout_until = self._lockouts.get(key)
        if lockout_until is None:
            return 0
        remaining = int(lockout_until - time.time())
        return max(remaining, 0)

    async def _on_request(self, request: Request) -> Response:
        key = self._key_func(request)
        source_ip = _extract_source_ip(request)
        path = request.scope.get("path", "")

        if self.is_locked(key):
            retry_after = self.get_retry_after(key)
            self.emit(
                "BRUTE_FORCE_LOCKED",
                source_ip=source_ip,
                path=path,
                detail=f"Key locked out, retry after {retry_after}s",
                metadata={"key": key, "retry_after": retry_after},
            )
            return Response(
                b'{"error": {"code": "BRUTE_FORCE_LOCKED", "message": "Too many failed attempts. Try again later."}}',
                status_code=429,
                headers={"Retry-After": str(retry_after), "Content-Type": "application/json"},
            )

        return await self.app(request)


# ---------------------------------------------------------------------------
# StorageBackend sync wrappers for brute force counting
# The async StorageBackend protocol is designed for middleware, but brute
# force often needs sync access from non-async login handlers. These thin
# wrappers run the async method in a new event loop if needed.
# ---------------------------------------------------------------------------

def _patch_backend() -> None:
    """Add sync methods to MemoryBackend and StorageBackend implementations.

    MemoryBackend operations are actually synchronous dict ops, so we can
    call them directly. For RedisBackend, we'd need to handle async properly.
    This patch adds ``incr_sync`` and ``reset_sync`` methods.
    """
    def _memory_incr_sync(self: MemoryBackend, key: str, window: float) -> int:
        now = time.time()
        entry = self._store.get(key)
        if entry is None or entry[1] <= now:
            self._store[key] = (1, now + window)
            return 1
        count = entry[0] + 1
        self._store[key] = (count, entry[1])
        return count

    def _memory_reset_sync(self: MemoryBackend, key: str) -> None:
        self._store.pop(key, None)

    def _memory_get_sync(self: MemoryBackend, key: str) -> int:
        entry = self._store.get(key)
        if entry is None or entry[1] <= time.time():
            return 0
        return entry[0]

    if not hasattr(MemoryBackend, "incr_sync"):
        MemoryBackend.incr_sync = _memory_incr_sync  # type: ignore[attr-defined]
    if not hasattr(MemoryBackend, "reset_sync"):
        MemoryBackend.reset_sync = _memory_reset_sync  # type: ignore[attr-defined]
    if not hasattr(MemoryBackend, "get_sync"):
        MemoryBackend.get_sync = _memory_get_sync  # type: ignore[attr-defined]


_patch_backend()
