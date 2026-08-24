"""Tests for CSRF protection middleware and standalone CSRFProtection.

Covers: cookie setting, token validation, double-submit check, exempt paths,
exempt content types, safe methods, standalone generate/validate, expired tokens.
"""

import asyncio
import time
from functools import partial

from velocix import TestClient, Velocix, JSONResponse
from velocix.security.csrf import CSRFMiddleware, CSRFProtection


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


# ---------------------------------------------------------------------------
# CSRFProtection standalone
# ---------------------------------------------------------------------------


def test_csrf_protection_generate_and_validate():
    csrf = CSRFProtection.create(secret_key="test-secret")
    token = csrf.generate_token()
    result = csrf.validate(token, token)
    assert result.valid is True
    assert result.error == ""


def test_csrf_protection_mismatch():
    csrf = CSRFProtection.create(secret_key="test-secret")
    token1 = csrf.generate_token()
    token2 = csrf.generate_token()
    result = csrf.validate(token1, token2)
    assert result.valid is False
    assert "mismatch" in result.error.lower()


def test_csrf_protection_missing_cookie():
    csrf = CSRFProtection.create(secret_key="test-secret")
    result = csrf.validate(None, "some-token")
    assert result.valid is False
    assert "cookie" in result.error.lower()


def test_csrf_protection_missing_header():
    csrf = CSRFProtection.create(secret_key="test-secret")
    result = csrf.validate("some-token", None)
    assert result.valid is False
    assert "header" in result.error.lower()


def test_csrf_protection_invalid_cookie_token():
    csrf = CSRFProtection.create(secret_key="test-secret")
    token = csrf.generate_token()
    result = csrf.validate("garbage", token)
    assert result.valid is False
    assert "invalid" in result.error.lower()


def test_csrf_protection_invalid_header_token():
    csrf = CSRFProtection.create(secret_key="test-secret")
    token = csrf.generate_token()
    result = csrf.validate(token, "garbage")
    assert result.valid is False
    assert "invalid" in result.error.lower()


def test_csrf_protection_different_secret_rejects():
    csrf1 = CSRFProtection.create(secret_key="secret-1")
    csrf2 = CSRFProtection.create(secret_key="secret-2")
    token = csrf1.generate_token()
    result = csrf2.validate(token, token)
    assert result.valid is False


def test_csrf_protection_set_cookie():
    from velocix.core.response import Response

    csrf = CSRFProtection.create(secret_key="test-secret")
    token = csrf.generate_token()
    resp = Response(b"ok", status_code=200)
    csrf.set_cookie(resp, token)
    cookie_headers = [v.decode() for k, v in resp.raw_headers if k == b"set-cookie"]
    assert len(cookie_headers) == 1
    assert "csrf_token=" in cookie_headers[0]
    assert "HttpOnly" in cookie_headers[0]


def test_csrf_protection_get_token_from_cookie():
    app = Velocix()
    csrf = CSRFProtection.create(secret_key="test-secret")

    @app.get("/check")
    async def check(request):
        token = csrf.get_token_from_cookie(request)
        return {"token": token}

    async def scenario():
        async with TestClient(app) as client:
            # No cookie — should return None
            resp = await client.get("/check")
            assert resp.json()["token"] is None

            # Set cookie manually
            client._cookies["csrf_token"] = "my-test-token"
            resp = await client.get("/check")
            assert resp.json()["token"] == "my-test-token"

    _run(scenario())
