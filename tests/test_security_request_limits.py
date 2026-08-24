"""Tests for request size limit middleware and standalone RequestLimits.

Covers: body size, header count, header size, URL length, Content-Length check,
standalone check() method, and streaming body enforcement.
"""

import asyncio
from functools import partial

from velocix import TestClient, Velocix
from velocix.security.request_limits import (
    RequestLimits,
    RequestLimitsMiddleware,
)


def _run(coro):
    return asyncio.run(coro)


def _app_with_limits(**kwargs):
    app = Velocix()

    @app.get("/ping")
    async def ping(request):
        return {"ok": True}

    @app.post("/data")
    async def data(request):
        return {"ok": True}

    app.add_middleware(partial(RequestLimitsMiddleware, **kwargs))
    return app


# ---------------------------------------------------------------------------
# RequestLimitsMiddleware — header count
# ---------------------------------------------------------------------------


def test_headers_within_limit():
    app = _app_with_limits(max_headers=10)

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/ping")
            assert resp.status_code == 200

    _run(scenario())


def test_headers_exceeds_limit():
    """Test header count check. TestClient doesn't add implicit headers,
    so we construct a scope with too many headers directly.
    """
    async def scenario():
        from velocix.core.request import Request
        from velocix.core.response import Response
        from velocix.security.request_limits import RequestLimitsMiddleware

        async def app(request):
            return Response(b"ok", status_code=200)

        middleware = RequestLimitsMiddleware(app, max_headers=2)

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/ping",
            "query_string": b"",
            "headers": [
                (b"h1", b"v1"),
                (b"h2", b"v2"),
                (b"h3", b"v3"),
            ],
            "server": ("test", 80),
            "client": ("test", 50000),
        }
        request = Request(scope, receive=None)
        resp = await middleware(request)
        assert resp.status_code == 431
        import orjson
        body = orjson.loads(resp.body)
        assert body["error"]["code"] == "REQUEST_HEADERS_TOO_MANY"

    _run(scenario())


# ---------------------------------------------------------------------------
# RequestLimitsMiddleware — URL length
# ---------------------------------------------------------------------------


def test_url_within_limit():
    app = _app_with_limits(max_url_length=200)

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/ping")
            assert resp.status_code == 200

    _run(scenario())


def test_url_exceeds_limit():
    app = _app_with_limits(max_url_length=10)

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/ping?verylongquery=value")
            assert resp.status_code == 414
            assert resp.json()["error"]["code"] == "REQUEST_URI_TOO_LONG"

    _run(scenario())


# ---------------------------------------------------------------------------
# RequestLimitsMiddleware — body size via Content-Length
# ---------------------------------------------------------------------------


def test_body_within_limit():
    app = _app_with_limits(max_body_size=1024)

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.post("/data", json={"small": "data"})
            assert resp.status_code == 200

    _run(scenario())


def test_body_exceeds_limit():
    """Test body size check via Content-Length header.

    TestClient doesn't add Content-Length to scope, so we construct
    a scope manually and call the middleware directly.
    """
    async def scenario():
        from velocix.core.request import Request
        from velocix.core.response import Response
        from velocix.security.request_limits import RequestLimitsMiddleware

        async def app(request):
            return Response(b"ok", status_code=200)

        middleware = RequestLimitsMiddleware(app, max_body_size=100)

        # Scope with Content-Length exceeding limit
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/data",
            "query_string": b"",
            "headers": [(b"content-length", b"500")],
            "server": ("test", 80),
            "client": ("test", 50000),
        }
        request = Request(scope, receive=None)
        resp = await middleware(request)
        assert resp.status_code == 413
        import orjson
        body = orjson.loads(resp.body)
        assert body["error"]["code"] == "REQUEST_BODY_TOO_LARGE"

    _run(scenario())


# ---------------------------------------------------------------------------
# RequestLimitsMiddleware — disable individual limits
# ---------------------------------------------------------------------------


def test_disabled_body_limit():
    app = _app_with_limits(max_body_size=None)

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.post("/data", json={"data": "x" * 10000})
            assert resp.status_code == 200

    _run(scenario())


def test_disabled_url_limit():
    app = _app_with_limits(max_url_length=None)

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/ping?" + "a=" + "b" * 5000)
            assert resp.status_code == 200

    _run(scenario())


# ---------------------------------------------------------------------------
# RequestLimits standalone
# ---------------------------------------------------------------------------


def test_standalone_check_within_limits():
    limits = RequestLimits.create(max_body_size=1024, max_headers=50)
    scope = {
        "path": "/test",
        "headers": [(b"content-length", b"512")],
    }
    result = limits.check(scope)
    assert result.ok is True


def test_standalone_check_body_exceeds():
    limits = RequestLimits.create(max_body_size=100)
    scope = {
        "path": "/test",
        "headers": [(b"content-length", b"200")],
    }
    result = limits.check(scope)
    assert result.ok is False
    assert result.status_code == 413
    assert result.code == "REQUEST_BODY_TOO_LARGE"


def test_standalone_check_url_exceeds():
    limits = RequestLimits.create(max_url_length=10)
    scope = {
        "path": "/very/long/path/that/exceeds/limit",
        "headers": [],
    }
    result = limits.check(scope)
    assert result.ok is False
    assert result.status_code == 414


def test_standalone_check_too_many_headers():
    limits = RequestLimits.create(max_headers=3)
    scope = {
        "path": "/test",
        "headers": [
            (b"h1", b"v1"),
            (b"h2", b"v2"),
            (b"h3", b"v3"),
            (b"h4", b"v4"),
        ],
    }
    result = limits.check(scope)
    assert result.ok is False
    assert result.status_code == 431
    assert result.code == "REQUEST_HEADERS_TOO_MANY"


def test_standalone_check_headers_too_large():
    limits = RequestLimits.create(max_header_size=20)
    scope = {
        "path": "/test",
        "headers": [
            (b"very-long-header-name", b"very-long-header-value-that-is-really-long"),
        ],
    }
    result = limits.check(scope)
    assert result.ok is False
    assert result.status_code == 431
    assert result.code == "REQUEST_HEADERS_TOO_LARGE"


def test_standalone_check_no_content_length_passes():
    limits = RequestLimits.create(max_body_size=10)
    scope = {
        "path": "/test",
        "headers": [],  # no content-length
    }
    result = limits.check(scope)
    assert result.ok is True


def test_standalone_check_all_disabled():
    limits = RequestLimits.create(
        max_body_size=None,
        max_headers=None,
        max_header_size=None,
        max_url_length=None,
    )
    scope = {
        "path": "/test",
        "headers": [(b"h", b"v")],
    }
    result = limits.check(scope)
    assert result.ok is True
