"""
Request size limit middleware.

Rejects oversized requests before they reach handlers, preventing memory
exhaustion and denial-of-service attacks. Checks happen early in the
request cycle — before body is read, before handler runs.

Limits enforced:
- **Body size**: ``Content-Length`` header checked before body is consumed.
  For chunked transfers (no Content-Length), wraps ``receive`` to count
  bytes as they arrive and disconnects when the limit is exceeded.
  Returns 413 Payload Too Large.
- **Header count**: Number of request headers. Returns 431 Request Header
  Fields Too Large.
- **Header size**: Total size of all headers in bytes. Returns 431.
- **URL length**: Length of path + query string. Returns 414 URI Too Long.

All limits are configurable. Set to ``None`` to disable that check.

Usage as middleware::

    from functools import partial
    from velocix.security.request_limits import RequestLimitsMiddleware

    app.add_middleware(partial(
        RequestLimitsMiddleware,
        max_body_size=10 * 1024 * 1024,   # 10 MB
        max_headers=50,
        max_header_size=8192,              # 8 KB
        max_url_length=2048,
    ))

Usage as utility (no middleware)::

    from velocix.security.request_limits import RequestLimits

    limits = RequestLimits.create(max_body_size=10 * 1024 * 1024)

    result = limits.check(request.scope)
    if not result.ok:
        return JSONResponse({"error": result.error}, status_code=result.status_code)
"""

from collections.abc import Awaitable, Callable
from typing import Any

from velocix.core.request import Request
from velocix.core.response import Response
from velocix.security.base import EventCallback, Severity, SecurityMiddleware

# Default limits
DEFAULT_MAX_BODY_SIZE = 10 * 1024 * 1024  # 10 MB
DEFAULT_MAX_HEADERS = 50
DEFAULT_MAX_HEADER_SIZE = 8192  # 8 KB
DEFAULT_MAX_URL_LENGTH = 2048


class RequestLimitsMiddleware(SecurityMiddleware):
    """Rejects requests that exceed configured size limits.

    Args:
        app: Next middleware or handler.
        max_body_size: Maximum request body size in bytes. Checked via
            ``Content-Length`` header. ``None`` to disable.
        max_headers: Maximum number of request headers. ``None`` to disable.
        max_header_size: Maximum total size of all headers in bytes.
            ``None`` to disable.
        max_url_length: Maximum length of path + query string in bytes.
            ``None`` to disable.
        severity: Event severity level.
        on_event: Optional event callback.
    """

    severity = Severity.MEDIUM

    __slots__ = (
        "app",
        "_max_body_size",
        "_max_headers",
        "_max_header_size",
        "_max_url_length",
    )

    def __init__(
        self,
        app: Callable[[Request], Awaitable[Response]],
        max_body_size: int | None = DEFAULT_MAX_BODY_SIZE,
        max_headers: int | None = DEFAULT_MAX_HEADERS,
        max_header_size: int | None = DEFAULT_MAX_HEADER_SIZE,
        max_url_length: int | None = DEFAULT_MAX_URL_LENGTH,
        severity: Severity | None = None,
        on_event: EventCallback | None = None,
    ) -> None:
        super().__init__(app, severity=severity, on_event=on_event)
        self._max_body_size = max_body_size
        self._max_headers = max_headers
        self._max_header_size = max_header_size
        self._max_url_length = max_url_length

    async def _on_request(self, request: Request) -> Response:
        source_ip = ""
        client = request.scope.get("client")
        if client and len(client) >= 1:
            source_ip = str(client[0])

        path = request.scope.get("path", "")
        method = request.scope.get("method", "GET").upper()
        headers = request.scope.get("headers", [])

        # 1. Header count
        if self._max_headers is not None and len(headers) > self._max_headers:
            self.emit(
                "REQUEST_HEADERS_TOO_MANY",
                source_ip=source_ip,
                path=path,
                detail=f"Header count {len(headers)} exceeds limit {self._max_headers}",
                metadata={"header_count": len(headers), "limit": self._max_headers},
            )
            return Response(
                b'{"error": {"code": "REQUEST_HEADERS_TOO_MANY", "message": "Too many headers"}}',
                status_code=431,
                media_type="application/json",
            )

        # 2. Total header size
        if self._max_header_size is not None:
            total_size = sum(len(k) + len(v) for k, v in headers)
            if total_size > self._max_header_size:
                self.emit(
                    "REQUEST_HEADERS_TOO_LARGE",
                    source_ip=source_ip,
                    path=path,
                    detail=f"Header size {total_size} bytes exceeds limit {self._max_header_size}",
                    metadata={"header_size": total_size, "limit": self._max_header_size},
                )
                return Response(
                    b'{"error": {"code": "REQUEST_HEADERS_TOO_LARGE", "message": "Headers too large"}}',
                    status_code=431,
                    media_type="application/json",
                )

        # 3. URL length (path + query string)
        if self._max_url_length is not None:
            query_string = request.scope.get("query_string", b"")
            url_length = len(path.encode("utf-8")) + len(query_string)
            if url_length > self._max_url_length:
                self.emit(
                    "REQUEST_URI_TOO_LONG",
                    source_ip=source_ip,
                    path=path,
                    detail=f"URL length {url_length} exceeds limit {self._max_url_length}",
                    metadata={"url_length": url_length, "limit": self._max_url_length},
                )
                return Response(
                    b'{"error": {"code": "REQUEST_URI_TOO_LONG", "message": "URI too long"}}',
                    status_code=414,
                    media_type="application/json",
                )

        # 4. Body size (Content-Length header)
        if self._max_body_size is not None:
            for k, v in headers:
                if k == b"content-length":
                    try:
                        content_length = int(v.decode("latin-1"))
                        if content_length > self._max_body_size:
                            self.emit(
                                "REQUEST_BODY_TOO_LARGE",
                                source_ip=source_ip,
                                path=path,
                                detail=f"Body size {content_length} bytes exceeds limit {self._max_body_size}",
                                metadata={"body_size": content_length, "limit": self._max_body_size},
                            )
                            return Response(
                                b'{"error": {"code": "REQUEST_BODY_TOO_LARGE", "message": "Request body too large"}}',
                                status_code=413,
                                media_type="application/json",
                            )
                    except (ValueError, UnicodeDecodeError):
                        pass
                    break

        # 5. Streaming body size enforcement for chunked transfers
        #    When there's no Content-Length, wrap receive to count bytes
        #    as they arrive and disconnect when limit is exceeded.
        if self._max_body_size is not None:
            has_content_length = any(k == b"content-length" for k, _ in headers)
            if not has_content_length and method in ("POST", "PUT", "PATCH", "DELETE"):
                original_receive = request._receive
                accumulated = 0
                max_size = self._max_body_size

                async def _counting_receive() -> dict[str, Any]:
                    nonlocal accumulated
                    msg = await original_receive()
                    if msg["type"] == "http.request":
                        body = msg.get("body", b"")
                        accumulated += len(body)
                        if accumulated > max_size:
                            self.emit(
                                "REQUEST_BODY_TOO_LARGE",
                                source_ip=source_ip,
                                path=path,
                                detail=f"Streaming body size {accumulated} bytes exceeds limit {max_size}",
                                metadata={"body_size": accumulated, "limit": max_size},
                            )
                            return {"type": "http.disconnect"}
                    return msg

                request._receive = _counting_receive

        return await self.app(request)


# ---------------------------------------------------------------------------
# Standalone request limits utility — no middleware required
# ---------------------------------------------------------------------------


class LimitCheckResult:
    """Result of a request limits check."""

    __slots__ = ("ok", "error", "status_code", "code")

    def __init__(
        self, ok: bool, error: str = "", status_code: int = 200, code: str = ""
    ) -> None:
        self.ok = ok
        self.error = error
        self.status_code = status_code
        self.code = code


class RequestLimits:
    """Standalone request limits — check request scope without middleware.

    Use this when you want to enforce limits in specific handlers rather than
    applied globally via middleware.

    Usage::

        from velocix.security.request_limits import RequestLimits

        limits = RequestLimits.create(max_body_size=5 * 1024 * 1024)

        @app.post("/upload")
        async def upload(request: Request):
            result = limits.check(request.scope)
            if not result.ok:
                return JSONResponse({"error": result.error}, status_code=result.status_code)
            # ... process upload ...
    """

    __slots__ = ("_max_body_size", "_max_headers", "_max_header_size", "_max_url_length")

    def __init__(
        self,
        max_body_size: int | None = DEFAULT_MAX_BODY_SIZE,
        max_headers: int | None = DEFAULT_MAX_HEADERS,
        max_header_size: int | None = DEFAULT_MAX_HEADER_SIZE,
        max_url_length: int | None = DEFAULT_MAX_URL_LENGTH,
    ) -> None:
        self._max_body_size = max_body_size
        self._max_headers = max_headers
        self._max_header_size = max_header_size
        self._max_url_length = max_url_length

    @classmethod
    def create(
        cls,
        max_body_size: int | None = DEFAULT_MAX_BODY_SIZE,
        max_headers: int | None = DEFAULT_MAX_HEADERS,
        max_header_size: int | None = DEFAULT_MAX_HEADER_SIZE,
        max_url_length: int | None = DEFAULT_MAX_URL_LENGTH,
    ) -> "RequestLimits":
        """Create a standalone RequestLimits instance."""
        return cls(max_body_size, max_headers, max_header_size, max_url_length)

    def check(self, scope: dict[str, Any]) -> LimitCheckResult:
        """Check a request scope against all configured limits.

        Args:
            scope: ASGI request scope dict.

        Returns:
            LimitCheckResult with .ok=True if all checks pass.
        """
        path = scope.get("path", "")
        headers = scope.get("headers", [])

        # Header count
        if self._max_headers is not None and len(headers) > self._max_headers:
            return LimitCheckResult(
                False,
                f"Too many headers ({len(headers)} > {self._max_headers})",
                431,
                "REQUEST_HEADERS_TOO_MANY",
            )

        # Total header size
        if self._max_header_size is not None:
            total_size = sum(len(k) + len(v) for k, v in headers)
            if total_size > self._max_header_size:
                return LimitCheckResult(
                    False,
                    f"Headers too large ({total_size} > {self._max_header_size} bytes)",
                    431,
                    "REQUEST_HEADERS_TOO_LARGE",
                )

        # URL length
        if self._max_url_length is not None:
            query_string = scope.get("query_string", b"")
            url_length = len(path.encode("utf-8")) + len(query_string)
            if url_length > self._max_url_length:
                return LimitCheckResult(
                    False,
                    f"URI too long ({url_length} > {self._max_url_length} bytes)",
                    414,
                    "REQUEST_URI_TOO_LONG",
                )

        # Body size (Content-Length)
        if self._max_body_size is not None:
            for k, v in headers:
                if k == b"content-length":
                    try:
                        content_length = int(v.decode("latin-1"))
                        if content_length > self._max_body_size:
                            return LimitCheckResult(
                                False,
                                f"Body too large ({content_length} > {self._max_body_size} bytes)",
                                413,
                                "REQUEST_BODY_TOO_LARGE",
                            )
                    except (ValueError, UnicodeDecodeError):
                        pass
                    break

        return LimitCheckResult(True)
