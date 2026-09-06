"""Tests for CSRF protection middleware.

Covers: cookie setting, token validation, double-submit check, exempt paths,
exempt content types, safe methods.
"""

import asyncio
from functools import partial

from velocix import TestClient, Velocix
from velocix.security.csrf import CSRFMiddleware


def _run(coro):
    return asyncio.run(coro)


def _app_with_csrf(**kwargs):
    app = Velocix()

    @app.get("/page")
    async def get_page(request):
        return {"ok": True}

    @app.post("/page")
    async def post_page(request):
        return {"ok": True}

    @app.post("/api/webhook")
    async def webhook(request):
        return {"ok": True}

    app.add_middleware(partial(CSRFMiddleware, secret_key="test-secret", **kwargs))
    return app


# ---------------------------------------------------------------------------
# CSRFMiddleware — safe methods set cookie
# ---------------------------------------------------------------------------


def test_get_sets_csrf_cookie():
    app = _app_with_csrf()

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/page")
            assert resp.status_code == 200
            assert "set-cookie" in resp.headers
            assert "csrf_token=" in resp.headers["set-cookie"]

    _run(scenario())


def test_csrf_cookie_is_not_httponly():
    """The double-submit pattern requires client-side JS to read this cookie
    and echo it back as a header; HttpOnly would make that impossible,
    silently breaking CSRF protection for every real browser client."""
    app = _app_with_csrf()

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/page")
            assert "httponly" not in resp.headers["set-cookie"].lower()

    _run(scenario())


def test_get_with_existing_valid_cookie_does_not_reset():
    app = _app_with_csrf()

    async def scenario():
        async with TestClient(app) as client:
            # First GET sets the cookie
            resp1 = await client.get("/page")
            assert "set-cookie" in resp1.headers
            # Second GET with the cookie — should not reset
            resp2 = await client.get("/page")
            assert "set-cookie" not in resp2.headers

    _run(scenario())


# ---------------------------------------------------------------------------
# CSRFMiddleware — state-changing methods require token
# ---------------------------------------------------------------------------


def test_post_without_cookie_returns_403():
    app = _app_with_csrf()

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.post("/page")
            assert resp.status_code == 403
            assert resp.json()["error"]["code"] == "CSRF_COOKIE_MISSING"

    _run(scenario())


def test_post_with_cookie_but_no_header_returns_403():
    app = _app_with_csrf()

    async def scenario():
        async with TestClient(app) as client:
            # GET to set cookie
            await client.get("/page")
            # POST without X-CSRF-Token header
            resp = await client.post("/page")
            assert resp.status_code == 403
            assert resp.json()["error"]["code"] == "CSRF_HEADER_MISSING"

    _run(scenario())


def test_post_with_mismatched_tokens_returns_403():
    app = _app_with_csrf()

    async def scenario():
        async with TestClient(app) as client:
            # GET to set cookie
            await client.get("/page")
            # POST with wrong token in header
            resp = await client.post(
                "/page",
                headers={"x-csrf-token": "wrong-token-value"},
            )
            assert resp.status_code == 403

    _run(scenario())


def test_post_with_matching_tokens_succeeds():
    app = _app_with_csrf()

    async def scenario():
        async with TestClient(app) as client:
            # GET to set cookie
            resp = await client.get("/page")
            cookie_value = client._cookies.get("csrf_token")
            assert cookie_value is not None
            # POST with matching token in header
            resp = await client.post(
                "/page",
                headers={"x-csrf-token": cookie_value},
            )
            assert resp.status_code == 200

    _run(scenario())


# ---------------------------------------------------------------------------
# CSRFMiddleware — exempt paths
# ---------------------------------------------------------------------------


def test_exempt_path_skips_csrf():
    app = _app_with_csrf(exempt_paths=["/api/webhook"])

    async def scenario():
        async with TestClient(app) as client:
            # POST to exempt path — no cookie needed
            resp = await client.post("/api/webhook")
            assert resp.status_code == 200

    _run(scenario())


# ---------------------------------------------------------------------------
# CSRFMiddleware — exempt content types
# ---------------------------------------------------------------------------


def test_exempt_content_type_skips_csrf():
    app = _app_with_csrf(exempt_content_types=["application/json"])

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.post(
                "/page",
                json={"data": "test"},
            )
            assert resp.status_code == 200

    _run(scenario())
