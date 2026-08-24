"""
CSRF protection middleware using the Double Submit Cookie pattern.

How it works:
1. On any request without a CSRF cookie, the middleware sets one (HMAC-signed token).
2. On state-changing requests (POST, PUT, PATCH, DELETE), the middleware checks
   that the ``X-CSRF-Token`` header matches the ``csrf_token`` cookie.
3. If they don't match, the request is blocked with 403.

The token is signed with itsdangerous.TimestampSigner so it includes a timestamp
and can be verified for freshness (optional max age).

Exempt:
- Paths in ``exempt_paths`` (e.g. ``["/api/webhook"]``)
- Content types in ``exempt_content_types`` (e.g. ``["application/json"]`` for
  API-only apps using JWT — CSRF doesn't apply when auth is via Authorization header)
- Safe methods (GET, HEAD, OPTIONS, TRACE) never require a token — they only
  set the cookie if missing.

Usage::

    from functools import partial
    from velocix.security.csrf import CSRFMiddleware

    app.add_middleware(partial(CSRFMiddleware, secret_key="your-secret"))

    # Or exempt all JSON APIs (they use JWT, not cookies):
    app.add_middleware(partial(
        CSRFMiddleware,
        secret_key="your-secret",
        exempt_content_types=["application/json"],
    ))
"""

import secrets
import time
from collections.abc import Awaitable, Callable
from typing import Any

import itsdangerous

from velocix.core.request import Request
from velocix.core.response import Response
from velocix.security.base import EventCallback, Severity, SecurityMiddleware


_DEFAULT_COOKIE_NAME = "csrf_token"
_DEFAULT_HEADER_NAME = "x-csrf-token"
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
_STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class CSRFMiddleware(SecurityMiddleware):
    """Double Submit Cookie CSRF protection.

    Args:
        app: Next middleware or handler.
        secret_key: HMAC signing key for tokens. Use a long random string.
        cookie_name: Name of the CSRF cookie (default ``csrf_token``).
        header_name: Name of the header the client must send (default ``x-csrf-token``).
        cookie_path: Path attribute on the CSRF cookie (default ``/``).
        cookie_secure: Only send cookie over HTTPS (default ``False``).
        cookie_samesite: SameSite attribute (default ``lax``).
        max_age: Maximum token age in seconds. ``None`` means no expiry check
            (token is valid until cookie expires). Default ``None``.
        exempt_paths: List of path prefixes that skip CSRF checks entirely.
        exempt_content_types: List of content types that skip CSRF checks.
            Useful for API-only apps where auth is via Authorization header,
            not cookies — CSRF doesn't apply to those.
        severity: Event severity level.
        on_event: Optional event callback.
    """

    severity = Severity.HIGH

    __slots__ = (
        "app",
        "_signer",
        "_cookie_name",
        "_header_name",
        "_cookie_path",
        "_cookie_secure",
        "_cookie_samesite",
        "_max_age",
        "_exempt_paths",
        "_exempt_content_types",
    )

    def __init__(
        self,
        app: Callable[[Request], Awaitable[Response]],
        secret_key: str,
        cookie_name: str = _DEFAULT_COOKIE_NAME,
        header_name: str = _DEFAULT_HEADER_NAME,
        cookie_path: str = "/",
        cookie_secure: bool = False,
        cookie_samesite: str = "lax",
        max_age: int | None = None,
        exempt_paths: list[str] | None = None,
        exempt_content_types: list[str] | None = None,
        severity: Severity | None = None,
        on_event: EventCallback | None = None,
    ) -> None:
        super().__init__(app, severity=severity, on_event=on_event)
        self._signer = itsdangerous.TimestampSigner(secret_key)
        self._cookie_name = cookie_name
        self._header_name = header_name
        self._cookie_path = cookie_path
        self._cookie_secure = cookie_secure
        self._cookie_samesite = cookie_samesite
        self._max_age = max_age
        self._exempt_paths = exempt_paths or []
        self._exempt_content_types = exempt_content_types or []

    def _is_exempt(self, request: Request) -> bool:
        """Check if this request is exempt from CSRF checks."""
        path = request.scope.get("path", "")

        for prefix in self._exempt_paths:
            if path == prefix or path.startswith(prefix + "/"):
                return True

        if self._exempt_content_types:
            for k, v in request.scope.get("headers", []):
                if k == b"content-type":
                    ct = v.decode("latin-1").split(";")[0].strip().lower()
                    if ct in self._exempt_content_types:
                        return True
                    break

        return False

    def _generate_token(self) -> str:
        """Generate a new CSRF token (random + signed timestamp)."""
        random_part = secrets.token_urlsafe(32)
        return self._signer.sign(random_part).decode("latin-1")

    def _validate_token(self, token: str) -> bool:
        """Validate a CSRF token. Returns True if valid."""
        try:
            self._signer.unsign(token, max_age=self._max_age)
            return True
        except (itsdangerous.BadSignature, itsdangerous.SignatureExpired):
            return False

    def _set_csrf_cookie(self, response: Response, token: str) -> None:
        """Set the CSRF cookie on the response."""
        response.raw_headers.append((
            b"set-cookie",
            (
                f"{self._cookie_name}={token}; "
                f"Path={self._cookie_path}; "
                f"SameSite={self._cookie_samesite}; "
                f"{'Secure; ' if self._cookie_secure else ''}"
                f"HttpOnly"
            ).encode("latin-1"),
        ))

    async def _on_request(self, request: Request) -> Response:
        source_ip = ""
        client = request.scope.get("client")
        if client and len(client) >= 1:
            source_ip = str(client[0])

        method = request.scope.get("method", "GET").upper()
        path = request.scope.get("path", "")

        # Exempt paths and content types skip entirely
        if self._is_exempt(request):
            return await self.app(request)

        # Read existing cookie
        cookie_header = b""
        for k, v in request.scope.get("headers", []):
            if k == b"cookie":
                cookie_header = v
                break

        existing_token = None
        if cookie_header:
            for part in cookie_header.decode("latin-1").split(";"):
                part = part.strip()
                if part.startswith(f"{self._cookie_name}="):
                    existing_token = part.split("=", 1)[1]
                    break

        # Safe methods: set cookie if missing, then pass through
        if method in _SAFE_METHODS:
            if existing_token is None or not self._validate_token(existing_token):
                response = await self.app(request)
                self._set_csrf_cookie(response, self._generate_token())
                return response
            return await self.app(request)

        # State-changing methods: validate token
        if method in _STATE_CHANGING_METHODS:
            # Read token from header
            header_token = None
            for k, v in request.scope.get("headers", []):
                if k == self._header_name.encode("latin-1"):
                    header_token = v.decode("latin-1")
                    break

            # Must have both cookie and header, and they must match
            if not existing_token:
                self.emit(
                    "CSRF_COOKIE_MISSING",
                    source_ip=source_ip,
                    path=path,
                    detail="CSRF cookie not set",
                )
                return Response(
                    b'{"error": {"code": "CSRF_COOKIE_MISSING", "message": "CSRF cookie not set. Make a GET request first to initialize."}}',
                    status_code=403,
                    media_type="application/json",
                )

            if not header_token:
                self.emit(
                    "CSRF_HEADER_MISSING",
                    source_ip=source_ip,
                    path=path,
                    detail=f"CSRF header '{self._header_name}' not provided",
                )
                return Response(
                    b'{"error": {"code": "CSRF_HEADER_MISSING", "message": "CSRF header not provided"}}',
                    status_code=403,
                    media_type="application/json",
                )

            if not self._validate_token(existing_token):
                self.emit(
                    "CSRF_TOKEN_INVALID",
                    source_ip=source_ip,
                    path=path,
                    detail="CSRF cookie token is invalid or expired",
                )
                return Response(
                    b'{"error": {"code": "CSRF_TOKEN_INVALID", "message": "CSRF cookie token invalid or expired"}}',
                    status_code=403,
                    media_type="application/json",
                )

            if not self._validate_token(header_token):
                self.emit(
                    "CSRF_TOKEN_INVALID",
                    source_ip=source_ip,
                    path=path,
                    detail="CSRF header token is invalid or expired",
                )
                return Response(
                    b'{"error": {"code": "CSRF_TOKEN_INVALID", "message": "CSRF header token invalid or expired"}}',
                    status_code=403,
                    media_type="application/json",
                )

            # Both tokens valid — compare the raw values
            if existing_token != header_token:
                self.emit(
                    "CSRF_MISMATCH",
                    source_ip=source_ip,
                    path=path,
                    detail="CSRF cookie and header tokens do not match",
                )
                return Response(
                    b'{"error": {"code": "CSRF_MISMATCH", "message": "CSRF token mismatch"}}',
                    status_code=403,
                    media_type="application/json",
                )

            # Token valid and matches — pass through
            return await self.app(request)

        # Unknown method — pass through
        return await self.app(request)
