"""
Input sanitization middleware for XSS, SQL injection detection, and path traversal.

XSS: Uses nh3 (Rust-backed ammonia bindings) to strip dangerous HTML tags
from query params, headers, and form fields. JSON body fields are left
untouched — output encoding is the handler's responsibility.

SQLi: Regex-based detection of common injection patterns. This is a flagging
mechanism for audit logging, not a prevention mechanism — prevention is
parameterized queries in your database layer.

Path traversal: Rejects any request path containing ``..`` segments.

Action modes:
- BLOCK: Return 400 immediately.
- SANITIZE: Strip dangerous content and pass through.
- LOG: Log the violation and pass through unchanged.
"""

import re
from collections.abc import Awaitable, Callable
from enum import Enum
from typing import Any

import nh3

from velocix.core.request import Request
from velocix.core.response import Response
from velocix.security.base import EventCallback, Severity, SecurityMiddleware


class SanitizeAction(Enum):
    """What to do when sanitization detects something."""

    BLOCK = "block"
    SANITIZE = "sanitize"
    LOG = "log"


# ---------------------------------------------------------------------------
# SQLi detection patterns — flags obvious injection attempts
# ---------------------------------------------------------------------------

_SQLI_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:'\s*(?:OR|AND)\s+['\d])", re.IGNORECASE),
    re.compile(r"(?:;\s*(?:DROP|DELETE|INSERT|UPDATE|ALTER|CREATE)\s)", re.IGNORECASE),
    re.compile(r"(?:UNION\s+(?:ALL\s+)?SELECT)", re.IGNORECASE),
    re.compile(r"(?:--\s*$)|(?:/\*.*?\*/)", re.IGNORECASE | re.DOTALL),
    re.compile(r"(?:'\s*;\s*$)", re.IGNORECASE),
    re.compile(r"(?:0x[0-9a-fA-F]{4,})", re.IGNORECASE),
    re.compile(r"(?:CHAR\s*\()", re.IGNORECASE),
    re.compile(r"(?:BENCHMARK\s*\()", re.IGNORECASE),
    re.compile(r"(?:SLEEP\s*\()", re.IGNORECASE),
    re.compile(r"(?:LOAD_FILE\s*\()", re.IGNORECASE),
    re.compile(r"(?:INTO\s+(?:OUTFILE|DUMPFILE))", re.IGNORECASE),
]


def detect_sqli(value: str) -> bool:
    """Return True if ``value`` matches a common SQL injection pattern.

    This is a heuristic for flagging, not a substitute for parameterized queries.
    """
    for pattern in _SQLI_PATTERNS:
        if pattern.search(value):
            return True
    return False


def _has_html(value: str) -> bool:
    """Return True if ``value`` contains HTML tags that nh3 would sanitize."""
    return nh3.clean(value) != value


def _has_path_traversal(path: str) -> bool:
    """Return True if ``path`` contains ``..`` segments."""
    parts = path.split("/")
    return any(p == ".." for p in parts)


def _extract_source_ip(request: Request) -> str:
    client = request.scope.get("client")
    if client and len(client) >= 1:
        return str(client[0])
    return ""


# ---------------------------------------------------------------------------
# Query string sanitization
# ---------------------------------------------------------------------------


def _sanitize_query_string(query_string: bytes, action: SanitizeAction) -> tuple[bytes, list[str]]:
    """Sanitize a raw query string. Returns (possibly modified) bytes and violation descriptions."""
    if not query_string:
        return query_string, []

    decoded = query_string.decode("latin-1")
    violations: list[str] = []
    changed = False

    for part in decoded.split("&"):
        if "=" not in part:
            continue
        _key, value = part.split("=", 1)
        value_decoded = _url_decode(value)

        # XSS: strip HTML tags from query values
        if _has_html(value_decoded):
            violations.append(f"xss_in_query:{_key}")
            if action == SanitizeAction.SANITIZE:
                clean_value = _url_encode(nh3.clean(value_decoded))
                decoded = decoded.replace(value, clean_value)
                changed = True

        # SQLi: flag but don't modify
        if detect_sqli(value_decoded):
            violations.append(f"sqli_in_query:{_key}")

    if changed:
        return decoded.encode("latin-1"), violations
    return query_string, violations


def _url_decode(s: str) -> str:
    """Minimal URL-decode for query parameter values."""
    from urllib.parse import unquote
    return unquote(s.replace("+", " "))


def _url_encode(s: str) -> str:
    """Minimal URL-encode for query parameter values."""
    from urllib.parse import quote
    return quote(s, safe="")


# ---------------------------------------------------------------------------
# Header sanitization
# ---------------------------------------------------------------------------


def _sanitize_headers(
    headers: list[tuple[bytes, bytes]], action: SanitizeAction
) -> tuple[list[tuple[bytes, bytes]], list[str]]:
    """Sanitize request headers. Returns (possibly modified) headers and violations."""
    violations: list[str] = []
    cleaned: list[tuple[bytes, bytes]] = []

    for key, value in headers:
        value_str = value.decode("latin-1")
        original = value_str

        # XSS: strip HTML tags from header values (except content-type etc.)
        key_lower = key.lower()
        if key_lower not in (b"content-type", b"content-length", b"host", b"authorization"):
            if _has_html(value_str):
                violations.append(f"xss_in_header:{key.decode('latin-1')}")
                if action == SanitizeAction.SANITIZE:
                    value_str = nh3.clean(value_str)

        # Header injection: reject \\r\\n in header values
        if "\\r" in value_str or "\\n" in value_str:
            violations.append(f"header_injection:{key.decode('latin-1')}")
            if action == SanitizeAction.SANITIZE:
                value_str = value_str.replace("\\r", "").replace("\\n", "")

        # SQLi: flag in header values
        if detect_sqli(value_str):
            violations.append(f"sqli_in_header:{key.decode('latin-1')}")

        if value_str != original:
            cleaned.append((key, value_str.encode("latin-1")))
        else:
            cleaned.append((key, value))

    return cleaned, violations


# ---------------------------------------------------------------------------
# Body sanitization (JSON)
# ---------------------------------------------------------------------------


def _sanitize_json_body(body: bytes, action: SanitizeAction) -> tuple[bytes, list[str]]:
    """Scan JSON body string values for XSS/SQLi. Returns violations.

    Does NOT modify the body — output encoding is the handler's job.
    Only flags violations for audit logging.
    """
    if not body:
        return body, []

    violations: list[str] = []
    try:
        import orjson
        data = orjson.loads(body)
        _scan_json_values(data, "", violations)
    except Exception:
        pass

    return body, violations


def _scan_json_values(obj: Any, prefix: str, violations: list[str]) -> None:
    """Recursively scan JSON values for XSS/SQLi patterns."""
    if isinstance(obj, str):
        if _has_html(obj):
            violations.append(f"xss_in_body:{prefix}" if prefix else "xss_in_body")
        if detect_sqli(obj):
            violations.append(f"sqli_in_body:{prefix}" if prefix else "sqli_in_body")
    elif isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else k
            _scan_json_values(v, path, violations)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            path = f"{prefix}[{i}]" if prefix else str(i)
            _scan_json_values(v, path, violations)


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------


class InputSanitizationMiddleware(SecurityMiddleware):
    """Sanitize all incoming request data for XSS, SQLi, and path traversal.

    Args:
        app: Next middleware or handler in the chain.
        xss_action: What to do with XSS violations (default: SANITIZE).
        sqli_action: What to do with SQLi detections (default: LOG).
        path_traversal_action: What to do with path traversal (default: BLOCK).
        scan_body: Whether to scan JSON request bodies (default: True).
            Body scanning only flags violations for audit — it does NOT
            modify the body. Output encoding is the handler's job.
        on_event: Optional callback for security events.
    """

    severity = Severity.HIGH

    def __init__(
        self,
        app: Callable[[Request], Awaitable[Response]],
        xss_action: SanitizeAction = SanitizeAction.SANITIZE,
        sqli_action: SanitizeAction = SanitizeAction.LOG,
        path_traversal_action: SanitizeAction = SanitizeAction.BLOCK,
        scan_body: bool = True,
        severity: Severity | None = None,
        on_event: EventCallback | None = None,
    ) -> None:
        super().__init__(app, severity=severity, on_event=on_event)
        self._xss_action = xss_action
        self._sqli_action = sqli_action
        self._path_traversal_action = path_traversal_action
        self._scan_body = scan_body

    async def _on_request(self, request: Request) -> Response:
        violations: list[str] = []
        source_ip = _extract_source_ip(request)
        path = request.scope.get("path", "")

        # 1. Path traversal check
        if _has_path_traversal(path):
            self.emit(
                "PATH_TRAVERSAL",
                source_ip=source_ip,
                path=path,
                detail=f"Path contains .. segments: {path}",
            )
            if self._path_traversal_action == SanitizeAction.BLOCK:
                return Response(
                    b'{"error": {"code": "PATH_TRAVERSAL", "message": "Path traversal detected"}}',
                    status_code=400,
                    media_type="application/json",
                )

        # 2. Query string sanitization
        original_qs = request.scope.get("query_string", b"")
        sanitized_qs, qs_violations = _sanitize_query_string(original_qs, self._xss_action)
        violations.extend(qs_violations)
        if sanitized_qs != original_qs:
            request.scope["query_string"] = sanitized_qs
            request._query_string = sanitized_qs
            request._query_params = None  # force re-parse

        # 3. Header sanitization
        original_headers = request.scope.get("headers", [])
        sanitized_headers, header_violations = _sanitize_headers(original_headers, self._xss_action)
        violations.extend(header_violations)
        if sanitized_headers != original_headers:
            request.scope["headers"] = sanitized_headers
            request._headers = None  # force re-parse

        # 4. SQLi in query string (independent of XSS action)
        if original_qs:
            decoded_qs = original_qs.decode("latin-1")
            for part in decoded_qs.split("&"):
                if "=" in part:
                    _, value = part.split("=", 1)
                    value_decoded = _url_decode(value)
                    if detect_sqli(value_decoded) and f"sqli_in_query:_qs" not in violations:
                        violations.append("sqli_in_query:_qs")

        # 5. Body scanning (flag only, never modify)
        if self._scan_body and request.scope.get("method", "GET") in ("POST", "PUT", "PATCH"):
            content_type = b""
            for k, v in request.scope.get("headers", []):
                if k == b"content-type":
                    content_type = v
                    break
            ct_str = content_type.decode("latin-1", errors="replace")
            if "application/json" in ct_str:
                body = await request.body()
                _, body_violations = _sanitize_json_body(body, self._sqli_action)
                violations.extend(body_violations)

        # 6. Emit events for all violations
        for v in violations:
            action = self._xss_action if "xss" in v else self._sqli_action if "sqli" in v else SanitizeAction.LOG
            self.emit(
                "INPUT_VIOLATION",
                source_ip=source_ip,
                path=path,
                detail=v,
                metadata={"violation": v, "action": action.value},
            )

        # 7. Block if any violation requires blocking
        should_block = any(
            ("xss" in v and self._xss_action == SanitizeAction.BLOCK)
            or ("sqli" in v and self._sqli_action == SanitizeAction.BLOCK)
            for v in violations
        )
        if should_block:
            return Response(
                b'{"error": {"code": "INPUT_VIOLATION", "message": "Potentially malicious input detected"}}',
                status_code=400,
                media_type="application/json",
            )

        return await self.app(request)


# ---------------------------------------------------------------------------
# Standalone sanitizer utility — no middleware required
# ---------------------------------------------------------------------------


class SanitizationResult:
    """Result of a sanitization check on a single value."""

    __slots__ = ("clean", "violations")

    def __init__(self, clean: str, violations: list[str]) -> None:
        self.clean = clean
        self.violations = violations


class InputSanitizer:
    """Standalone input sanitizer — check and clean values without middleware.

    Use this when you want to sanitize specific values in handlers rather than
    scanning every request via middleware.

    Usage::

        from velocix.security.input_sanitization import InputSanitizer

        sanitizer = InputSanitizer.create()

        @app.post("/comment")
        async def post_comment(request: Request):
            data = await request.json()
            # Sanitize the title field
            result = sanitizer.sanitize_value(data["title"])
            if result.violations:
                return JSONResponse({"error": "Invalid input"}, status_code=400)
            # Use result.clean safely

        # Check a URL path
        if sanitizer.has_path_traversal(request.url.path):
            return JSONResponse({"error": "Bad path"}, status_code=400)
    """

    __slots__ = ("_xss_action", "_sqli_action")

    def __init__(
        self,
        xss_action: SanitizeAction = SanitizeAction.SANITIZE,
        sqli_action: SanitizeAction = SanitizeAction.LOG,
    ) -> None:
        self._xss_action = xss_action
        self._sqli_action = sqli_action

    @classmethod
    def create(
        cls,
        xss_action: SanitizeAction = SanitizeAction.SANITIZE,
        sqli_action: SanitizeAction = SanitizeAction.LOG,
    ) -> "InputSanitizer":
        """Create a standalone InputSanitizer.

        Args:
            xss_action: What to do with XSS violations.
            sqli_action: What to do with SQLi detections.
        """
        return cls(xss_action, sqli_action)

    def sanitize_value(self, value: str) -> SanitizationResult:
        """Check a single string value for XSS and SQLi. Returns cleaned value + violations."""
        violations: list[str] = []
        clean = value

        # XSS
        if _has_html(value):
            violations.append("xss")
            if self._xss_action == SanitizeAction.SANITIZE:
                clean = nh3.clean(clean)
            elif self._xss_action == SanitizeAction.BLOCK:
                return SanitizationResult(value, violations)

        # SQLi
        if detect_sqli(value):
            violations.append("sqli")

        return SanitizationResult(clean, violations)

    def has_xss(self, value: str) -> bool:
        """Return True if value contains XSS-suspicious HTML."""
        return _has_html(value)

    def has_sqli(self, value: str) -> bool:
        """Return True if value matches SQL injection patterns."""
        return detect_sqli(value)

    def has_path_traversal(self, path: str) -> bool:
        """Return True if path contains ``..`` segments."""
        return _has_path_traversal(path)

    def sanitize_query_string(self, query_string: bytes) -> tuple[bytes, list[str]]:
        """Sanitize a raw query string. Returns (possibly modified) bytes and violations."""
        return _sanitize_query_string(query_string, self._xss_action)

    def scan_json_body(self, body: bytes) -> list[str]:
        """Scan a JSON body for XSS/SQLi. Returns list of violation descriptions."""
        _, violations = _sanitize_json_body(body, self._sqli_action)
        return violations
