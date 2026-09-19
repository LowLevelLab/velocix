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
