"""Regression tests: middleware used to be entirely skipped for any response
built from an exception -- a router 404/405, or a handler-raised
HTTPException -- because exceptions unwound past every middleware's own
`response = await self.app(request)` call instead of that call ever
returning a Response. Only the success path ever reached a middleware's
post-processing (adding a header, counting a metric, etc).
"""

import asyncio

from velocix import TestClient, Velocix
from velocix.core.exceptions import NotFound
from velocix.core.middleware import BaseMiddleware


def _run(coro):
    return asyncio.run(coro)


class _TagMiddleware(BaseMiddleware):
    """Marks every response that passes through it, success or error."""

    async def __call__(self, request):
        response = await self.app(request)
        response.headers["X-Tagged"] = "yes"
        return response


def test_router_404_still_gets_middleware_effects():
    app = Velocix()

    @app.get("/known")
    async def known():
        return {}

    app.add_middleware(_TagMiddleware)

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/does-not-exist")
            assert resp.status_code == 404
            assert resp.headers.get("X-Tagged") == "yes"

    _run(scenario())


def test_handler_raised_exception_still_gets_middleware_effects():
    app = Velocix()

    @app.get("/posts/{post_id}")
    async def get_post(post_id: int):
        raise NotFound(f"Post {post_id} not found")

    app.add_middleware(_TagMiddleware)

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/posts/999")
            assert resp.status_code == 404
            assert resp.headers.get("X-Tagged") == "yes"

    _run(scenario())


def test_dynamic_route_path_params_still_bind_with_middleware():
    """Resolution is deferred into the middleware-wrapped path when
    middleware is configured; the resolved path_params must survive that,
    or every dynamic route fails required-param validation (422) instead
    of ever reaching the handler."""
    app = Velocix()

    @app.get("/posts/{post_id}")
    async def get_post(post_id: int):
        return {"post_id": post_id}

    app.add_middleware(_TagMiddleware)

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/posts/42")
            assert resp.status_code == 200
            assert resp.json() == {"post_id": 42}
            assert resp.headers.get("X-Tagged") == "yes"

    _run(scenario())


def test_success_path_unaffected():
    app = Velocix()

    @app.get("/ok")
    async def ok():
        return {"ok": True}

    app.add_middleware(_TagMiddleware)

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/ok")
            assert resp.status_code == 200
            assert resp.headers.get("X-Tagged") == "yes"

    _run(scenario())
