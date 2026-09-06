"""
Security middleware base classes and shared infrastructure.

Provides SecurityMiddleware (base for all security middleware),
SecurityEvent (structured event for audit logging),
HookManager (runs registered security hooks per request),
and StorageBackend (pluggable counting backend for rate limiting / brute force).
"""

import time
from collections.abc import Awaitable, Callable
from enum import IntEnum
from typing import Any, Protocol, runtime_checkable

from velocix.core.middleware import BaseMiddleware
from velocix.core.request import Request
from velocix.core.response import Response


class Severity(IntEnum):
    """Security event severity levels."""

    LOW = 10
    MEDIUM = 20
    HIGH = 30
    CRITICAL = 40


class SecurityEvent:
    """Structured security event for audit logging.

    Attributes:
        event_type: Category of event (e.g. RATE_LIMIT_HIT, CSRF_FAILURE).
        severity: How serious the event is.
        source_ip: Client IP address.
        path: Request path that triggered the event.
        detail: Human-readable description of what happened.
        metadata: Arbitrary extra data (username, key name, etc.).
        timestamp: Unix timestamp of when the event occurred.
    """

    __slots__ = (
        "event_type",
        "severity",
        "source_ip",
        "path",
        "detail",
        "metadata",
        "timestamp",
    )

    def __init__(
        self,
        event_type: str,
        severity: Severity,
        source_ip: str = "",
        path: str = "",
        detail: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.event_type = event_type
        self.severity = severity
        self.source_ip = source_ip
        self.path = path
        self.detail = detail
        self.metadata = metadata or {}
        self.timestamp = time.time()

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "event_type": self.event_type,
            "severity": self.severity.name,
            "source_ip": self.source_ip,
            "path": self.path,
            "detail": self.detail,
            "timestamp": self.timestamp,
        }
        if self.metadata:
            result["metadata"] = self.metadata
        return result


# Type alias for the event callback that security middleware emit events to.
EventCallback = Callable[[SecurityEvent], None]


def _default_event_callback(event: SecurityEvent) -> None:
    """Log security events to the velocix.security logger."""
    import logging

    logger = logging.getLogger("velocix.security")
    level = (
        logging.CRITICAL
        if event.severity >= Severity.CRITICAL
        else logging.ERROR
        if event.severity >= Severity.HIGH
        else logging.WARNING
        if event.severity >= Severity.MEDIUM
        else logging.INFO
    )
    logger.log(level, "%s: %s [%s]", event.event_type, event.detail, event.source_ip)


# ---------------------------------------------------------------------------
# Security hook protocol and manager
# ---------------------------------------------------------------------------


@runtime_checkable
class SecurityHook(Protocol):
    """Protocol for pluggable security hooks.

    Implement ``on_request`` to inspect/modify/block requests.
    Return a ``Response`` to block, or ``None`` to pass through.

    Hooks are called in priority order (lower = earlier). If two hooks
    have the same priority, registration order wins.
    """

    @property
    def priority(self) -> int:
        """Execution order. Lower runs first. Default 100."""
        ...

    async def on_request(self, request: Request) -> Response | None:
        """Inspect the request. Return a Response to block, None to continue."""
        ...


class HookManager(BaseMiddleware):
    """Runs registered security hooks in priority order before the handler.

    Each hook gets a chance to inspect the request. If any hook returns
    a Response, the request is blocked immediately and subsequent hooks
    and the handler are skipped.

    Args:
        app: Next middleware or handler in the chain.
        hooks: List of SecurityHook instances, or callables conforming
            to the protocol. They will be sorted by priority at init time.
    """

    __slots__ = ("app", "_hooks")

    def __init__(
        self,
        app: Callable[[Request], Awaitable[Response]],
        hooks: list[SecurityHook] | None = None,
    ) -> None:
        super().__init__(app)
        self._hooks: list[SecurityHook] = sorted(
            hooks or [], key=lambda h: getattr(h, "priority", 100)
        )

    def add_hook(self, hook: SecurityHook) -> None:
        """Add a hook and re-sort by priority."""
        self._hooks.append(hook)
        self._hooks.sort(key=lambda h: getattr(h, "priority", 100))

    async def __call__(self, request: Request) -> Response:
        for hook in self._hooks:
            result = await hook.on_request(request)
            if result is not None:
                return result
        return await self.app(request)


# ---------------------------------------------------------------------------
# Security middleware base class
# ---------------------------------------------------------------------------


class SecurityMiddleware(BaseMiddleware):
    """Base class for all Velocix security middleware.

    Subclasses override ``_on_request`` to implement their logic.
    The base class handles event emission and error containment.

    Args:
        app: Next middleware or handler in the chain.
        severity: Default severity for events emitted by this middleware.
        on_event: Callback invoked for every SecurityEvent. Defaults to
            logging to ``velocix.security``.
    """

    __slots__ = ("app", "_severity", "_on_event")

    severity: Severity = Severity.MEDIUM

    def __init__(
        self,
        app: Callable[[Request], Awaitable[Response]],
        severity: Severity | None = None,
        on_event: EventCallback | None = None,
    ) -> None:
        super().__init__(app)
        self._severity = severity or self.severity
        self._on_event = on_event or _default_event_callback

    def emit(self, event_type: str, detail: str = "", **kwargs: Any) -> SecurityEvent:
        """Create and emit a security event. Returns the event for inspection."""
        event = SecurityEvent(
            event_type=event_type,
            severity=self._severity,
            detail=detail,
            **kwargs,
        )
        self._on_event(event)
        return event

    async def __call__(self, request: Request) -> Response:
        # No try/except here on purpose: _on_request implementations call
        # self.app(request) themselves partway through their own checks, and
        # a bare `except Exception: return await self.app(request)` around
        # that can't tell "our own check logic raised" from "the call to
        # self.app(request) we already made raised" -- the latter meant a
        # single incoming request invoked the downstream handler chain
        # TWICE, risking real double side effects (e.g. a double DB write)
        # for any handler that raises after doing one.
        #
        # This used to be needed because an exception here would otherwise
        # propagate past every middleware, bypassing all of it. Velocix's
        # compiled middleware terminal now catches every exception (routing
        # failures and handler-raised HTTPExceptions alike) and converts it
        # to a Response before it ever reaches here, so self.app(request)
        # returning normally is already the common case; whatever's left
        # (a bug in this middleware's own pre-dispatch logic) is exactly
        # what should surface as a real error, not be silently retried.
        return await self._on_request(request)

    async def _on_request(self, request: Request) -> Response:
        """Override this to implement security logic.

        Return a Response to block the request, or call ``self.app(request)``
        to pass through to the next middleware/handler.
        """
        return await self.app(request)


# ---------------------------------------------------------------------------
# Pluggable storage backend for rate limiting / brute force / IP filter
# ---------------------------------------------------------------------------


@runtime_checkable
class StorageBackend(Protocol):
    """Protocol for pluggable counting storage used by rate limiting and brute force.

    Implementations must be async-safe. The Redis backend should use atomic
    operations (Lua scripts), not Python-level GET-then-INCR.
    """

    async def incr(self, key: str, window: float) -> int:
        """Increment counter for ``key``. Reset expiry to ``window`` seconds if new.
        Returns the new count."""
        ...

    async def get(self, key: str) -> int:
        """Get current count for ``key``. Returns 0 if key does not exist."""
        ...

    async def reset(self, key: str) -> None:
        """Delete the counter for ``key``."""
        ...


class MemoryBackend:
    """In-memory storage backend using a plain dict.

    Safe under async concurrency because incr/get/reset are synchronous
    dict operations — no ``await`` between read and write, so no coroutine
    switch can occur mid-operation within a single event-loop tick.
    """

    __slots__ = ("_store",)

    def __init__(self) -> None:
        self._store: dict[str, tuple[int, float]] = {}

    async def incr(self, key: str, window: float) -> int:
        now = time.time()
        entry = self._store.get(key)
        if entry is None or entry[1] <= now:
            self._store[key] = (1, now + window)
            return 1
        count = entry[0] + 1
        self._store[key] = (count, entry[1])
        return count

    async def get(self, key: str) -> int:
        entry = self._store.get(key)
        if entry is None or entry[1] <= time.time():
            return 0
        return entry[0]

    async def reset(self, key: str) -> None:
        self._store.pop(key, None)


class RedisBackend:
    """Redis storage backend using atomic Lua scripts.

    Requires ``redis.asyncio`` (installed via ``pip install redis``).

    Args:
        url: Redis connection URL (e.g. ``redis://localhost:6379/0``).
        prefix: Key prefix to namespace Velocix counters in Redis.
    """

    __slots__ = ("_client", "_prefix", "_incr_script")

    _INCR_SCRIPT = """
local current = redis.call('INCR', KEYS[1])
if current == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return current
"""

    def __init__(self, url: str = "redis://localhost:6379/0", prefix: str = "velocix:") -> None:
        try:
            import redis.asyncio as aioredis
        except ImportError as exc:
            raise ImportError(
                "RedisBackend requires the redis package: pip install redis"
            ) from exc
        self._client = aioredis.from_url(url, decode_responses=True)
        self._prefix = prefix
        self._incr_script = self._client.register_script(self._INCR_SCRIPT)

    def _key(self, key: str) -> str:
        return f"{self._prefix}{key}"

    async def incr(self, key: str, window: float) -> int:
        result = await self._incr_script(keys=[self._key(key)], args=[int(window)])
        return int(result)

    async def get(self, key: str) -> int:
        val = await self._client.get(self._key(key))
        return int(val) if val else 0

    async def reset(self, key: str) -> None:
        await self._client.delete(self._key(key))

    async def close(self) -> None:
        await self._client.aclose()
