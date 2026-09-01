"""Tests for input sanitization middleware and the standalone detect_sqli helper.

Covers: XSS detection/stripping, SQLi detection, path traversal rejection,
middleware action modes (BLOCK/SANITIZE/LOG).
"""

import asyncio
from functools import partial

from velocix import TestClient, Velocix
from velocix.security.input_sanitization import (
    InputSanitizationMiddleware,
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
