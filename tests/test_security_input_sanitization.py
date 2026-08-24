"""Tests for input sanitization middleware and standalone InputSanitizer.

Covers: XSS detection/stripping, SQLi detection, path traversal rejection,
middleware action modes (BLOCK/SANITIZE/LOG), standalone sanitize_value,
has_xss, has_sqli, has_path_traversal, sanitize_query_string, scan_json_body.
"""

import asyncio
from functools import partial

from velocix import TestClient, Velocix, JSONResponse
from velocix.security.input_sanitization import (
    InputSanitizationMiddleware,
    InputSanitizer,
    SanitizeAction,
    detect_sqli,
)


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# detect_sqli (standalone function)
# ---------------------------------------------------------------------------


def test_detect_sqli_or_1_eq_1():
    assert detect_sqli("' OR 1=1 --") is True


def test_detect_sqli_drop_table():
    assert detect_sqli("'; DROP TABLE users;") is True


def test_detect_sqli_union_select():
    assert detect_sqli("1 UNION SELECT * FROM users") is True


def test_detect_sqli_sleep():
    assert detect_sqli("1 AND SLEEP(5)") is True


def test_detect_sqli_hex_literal():
    assert detect_sqli("0x41424344") is True


def test_detect_sqli_clean_input():
    assert detect_sqli("hello world") is False


def test_detect_sqli_normal_number():
    assert detect_sqli("42") is False


# ---------------------------------------------------------------------------
# InputSanitizer standalone
# ---------------------------------------------------------------------------


def test_sanitize_value_xss_strips_tags():
    sanitizer = InputSanitizer.create(xss_action=SanitizeAction.SANITIZE)
    result = sanitizer.sanitize_value("<script>alert(1)</script>")
    assert "xss" in result.violations
    assert "<script>" not in result.clean


def test_sanitize_value_xss_block():
    sanitizer = InputSanitizer.create(xss_action=SanitizeAction.BLOCK)
    result = sanitizer.sanitize_value("<script>alert(1)</script>")
    assert "xss" in result.violations
    assert result.clean == "<script>alert(1)</script>"


def test_sanitize_value_xss_log():
    sanitizer = InputSanitizer.create(xss_action=SanitizeAction.LOG)
    result = sanitizer.sanitize_value("<script>alert(1)</script>")
    assert "xss" in result.violations
    # LOG mode: value is unchanged
    assert result.clean == "<script>alert(1)</script>"


def test_sanitize_value_sqli_block():
    sanitizer = InputSanitizer.create(sqli_action=SanitizeAction.BLOCK)
    result = sanitizer.sanitize_value("'; DROP TABLE users; --")
    assert "sqli" in result.violations
    assert result.clean == "'; DROP TABLE users; --"


def test_sanitize_value_sqli_log():
    sanitizer = InputSanitizer.create(sqli_action=SanitizeAction.LOG)
    result = sanitizer.sanitize_value("'; DROP TABLE users; --")
    assert "sqli" in result.violations
    # LOG: value unchanged
    assert result.clean == "'; DROP TABLE users; --"


def test_sanitize_value_clean_input():
    sanitizer = InputSanitizer.create()
    result = sanitizer.sanitize_value("hello world")
    assert result.violations == []
    assert result.clean == "hello world"


def test_sanitize_value_xss_and_sqli():
    sanitizer = InputSanitizer.create(
        xss_action=SanitizeAction.SANITIZE,
        sqli_action=SanitizeAction.LOG,
    )
    result = sanitizer.sanitize_value("<script>alert(' OR 1=1')</script>")
    assert "xss" in result.violations
    assert "sqli" in result.violations
    assert "<script>" not in result.clean


def test_has_xss():
    sanitizer = InputSanitizer.create()
    assert sanitizer.has_xss("<script>alert(1)</script>") is True
    assert sanitizer.has_xss("hello world") is False


def test_has_sqli():
    sanitizer = InputSanitizer.create()
    assert sanitizer.has_sqli("' OR 1=1 --") is True
    assert sanitizer.has_sqli("normal text") is False


def test_has_path_traversal():
    sanitizer = InputSanitizer.create()
    assert sanitizer.has_path_traversal("/api/../etc/passwd") is True
    assert sanitizer.has_path_traversal("/api/users") is False
    assert sanitizer.has_path_traversal("/api/users/..") is True


def test_sanitize_query_string():
    sanitizer = InputSanitizer.create(xss_action=SanitizeAction.SANITIZE)
    qs = b"name=<script>alert(1)</script>&age=25"
    cleaned, violations = sanitizer.sanitize_query_string(qs)
    assert any("xss" in v for v in violations)
    assert b"<script>" not in cleaned


def test_scan_json_body_xss():
    sanitizer = InputSanitizer.create()
    body = b'{"title": "<script>alert(1)</script>", "body": "clean"}'
    violations = sanitizer.scan_json_body(body)
    assert any("xss" in v for v in violations)


def test_scan_json_body_sqli():
    sanitizer = InputSanitizer.create()
    body = b'{"query": "\'; DROP TABLE users; --"}'
    violations = sanitizer.scan_json_body(body)
    assert any("sqli" in v for v in violations)


def test_scan_json_body_clean():
    sanitizer = InputSanitizer.create()
    body = b'{"title": "hello", "count": 42}'
    violations = sanitizer.scan_json_body(body)
    assert violations == []


# ---------------------------------------------------------------------------
# InputSanitizationMiddleware
# ---------------------------------------------------------------------------


def _app_with_sanitization(**kwargs):
    app = Velocix()

    @app.get("/ping")
    async def ping(request):
        return {"ok": True}

    @app.post("/data")
    async def data(request):
        return {"ok": True}

    @app.get("/api/../etc/passwd")
    async def traversal(request):
        return {"ok": True}

    app.add_middleware(partial(InputSanitizationMiddleware, **kwargs))
    return app


def test_middleware_allows_clean_input():
    app = _app_with_sanitization()

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/ping")
            assert resp.status_code == 200

    _run(scenario())


def test_middleware_blocks_path_traversal():
    app = _app_with_sanitization(path_traversal_action=SanitizeAction.BLOCK)

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/api/../etc/passwd")
            assert resp.status_code == 400
            data = resp.json()
            assert data["error"]["code"] == "PATH_TRAVERSAL"

    _run(scenario())


def test_middleware_sanitizes_xss_in_query():
    app = _app_with_sanitization(xss_action=SanitizeAction.SANITIZE)

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/ping?name=<script>alert(1)</script>")
            # Should pass through (sanitized, not blocked)
            assert resp.status_code == 200

    _run(scenario())


def test_middleware_blocks_xss():
    app = _app_with_sanitization(xss_action=SanitizeAction.BLOCK)

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/ping?name=<script>alert(1)</script>")
            assert resp.status_code == 400
            data = resp.json()
            assert data["error"]["code"] == "INPUT_VIOLATION"

    _run(scenario())


def test_middleware_logs_sqli_by_default():
    app = _app_with_sanitization()  # sqli_action defaults to LOG

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/ping?q='+OR+1=1+--")
            # LOG mode: passes through
            assert resp.status_code == 200

    _run(scenario())
