"""Tests for request size limit middleware.

Covers: body size, header count, header size, URL length, Content-Length check.
"""

import asyncio
from functools import partial

from velocix import TestClient, Velocix
from velocix.security.request_limits import RequestLimitsMiddleware


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
