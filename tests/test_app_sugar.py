"""Tests for the additive API-simplification sugar layer: add_middleware
kwargs support, enable_* convenience methods, and top-level exports.
"""

import asyncio
from functools import partial

from velocix import TestClient, Velocix
from velocix.core.middleware import BaseMiddleware


def _run(coro):
    return asyncio.run(coro)


class _RecordingMiddleware(BaseMiddleware):
    """Records the kwargs it was constructed with."""

    last_kwargs: dict = {}

    def __init__(self, app, **kwargs):
        super().__init__(app)
        _RecordingMiddleware.last_kwargs = kwargs

    async def __call__(self, request):
        return await self.app(request)


def test_add_middleware_accepts_kwargs_without_partial():
    app = Velocix()

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    app.add_middleware(_RecordingMiddleware, greeting="hi")

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/ping")
            assert resp.status_code == 200

    _run(scenario())
    assert _RecordingMiddleware.last_kwargs == {"greeting": "hi"}


def test_add_middleware_bare_class_still_works():
    app = Velocix()

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    app.add_middleware(_RecordingMiddleware)

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/ping")
            assert resp.status_code == 200

    _run(scenario())
    assert _RecordingMiddleware.last_kwargs == {}


def test_add_middleware_with_partial_still_works():
    app = Velocix()

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    app.add_middleware(partial(_RecordingMiddleware, greeting="via-partial"))

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/ping")
            assert resp.status_code == 200

    _run(scenario())
    assert _RecordingMiddleware.last_kwargs == {"greeting": "via-partial"}


def test_enable_cors_adds_allow_origin_header():
    app = Velocix()
    app.enable_cors(allow_origins=["https://example.com"])

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/ping", headers={"origin": "https://example.com"})
            assert resp.headers["access-control-allow-origin"] == "https://example.com"

    _run(scenario())


def test_enable_csrf_blocks_post_without_token():
    app = Velocix()
    app.enable_csrf(secret_key="test-secret")

    @app.post("/page")
    async def post_page():
        return {"ok": True}

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.post("/page")
            assert resp.status_code == 403
            assert resp.json()["error"]["code"] == "CSRF_COOKIE_MISSING"

    _run(scenario())


def test_enable_sessions_round_trips_value():
    app = Velocix()
    app.enable_sessions(secret_key="test-secret")

    @app.get("/set")
    async def set_session(request):
        request.session["user"] = "alice"
        return {"ok": True}

    @app.get("/read")
    async def read_session(request):
        return dict(request.session)

    async def scenario():
        async with TestClient(app) as client:
            await client.get("/set")
            resp = await client.get("/read")
            assert resp.json() == {"user": "alice"}

    _run(scenario())


def test_enable_rate_limit_returns_429_after_limit():
    app = Velocix()
    app.enable_rate_limit(limit=2, window=60)

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    async def scenario():
        async with TestClient(app) as client:
            assert (await client.get("/ping")).status_code == 200
            assert (await client.get("/ping")).status_code == 200
            resp = await client.get("/ping")
            assert resp.status_code == 429

    _run(scenario())


def test_enable_gzip_compresses_large_response():
    app = Velocix()
    app.enable_gzip(minimum_size=10)

    @app.get("/big")
    async def big():
        return {"data": "x" * 1000}

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/big", headers={"accept-encoding": "gzip"})
            assert resp.headers.get("content-encoding") == "gzip"

    _run(scenario())


def test_enable_trusted_hosts_rejects_unlisted_host():
    app = Velocix()
    app.enable_trusted_hosts(["example.com"])

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/ping", headers={"host": "evil.com"})
            assert resp.status_code == 400

    _run(scenario())


def test_top_level_exports_resolve():
    import msgspec

    from velocix import (
        BaseHTTPMiddleware,
        Body,
        CSRFMiddleware,
        GZipMiddleware,
        Struct,
        TrustedHostMiddleware,
    )

    assert Struct is msgspec.Struct
    assert Body is not None
    assert TrustedHostMiddleware is not None
    assert GZipMiddleware is not None
    assert BaseHTTPMiddleware is not None
    assert CSRFMiddleware is not None
