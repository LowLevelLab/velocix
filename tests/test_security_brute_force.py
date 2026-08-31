"""Tests for brute force protection middleware.

Covers: record_failure, mark_success, is_locked, get_retry_after,
middleware lockout, separate key tracking.
"""

import asyncio
from functools import partial

from velocix import TestClient, Velocix
from velocix.security.base import MemoryBackend
from velocix.security.brute_force import BruteForceProtection


def _run(coro):
    return asyncio.run(coro)


async def _passthrough_app(request):
    from velocix.core.response import Response

    return Response(b"ok", status_code=200)


def _make_bf(**kwargs):
    """Build a BruteForceProtection instance for direct method testing,
    without going through a Velocix app or the request-handling path."""
    return BruteForceProtection(_passthrough_app, **kwargs)


# ---------------------------------------------------------------------------
# BruteForceProtection — record_failure / is_locked / mark_success
# ---------------------------------------------------------------------------


def test_record_failure_increments():
    bf = _make_bf(max_attempts=5, window_seconds=60)
    assert bf.record_failure("user:1.2.3.4") == 1
    assert bf.record_failure("user:1.2.3.4") == 2
    assert bf.record_failure("user:1.2.3.4") == 3


def test_is_locked_after_threshold():
    bf = _make_bf(max_attempts=3, window_seconds=60, lockout_seconds=120)
    bf.record_failure("user:1")
    bf.record_failure("user:1")
    assert bf.is_locked("user:1") is False  # 2 < 3
    bf.record_failure("user:1")  # 3 >= 3, locked
    assert bf.is_locked("user:1") is True


def test_is_locked_returns_false_for_unknown_key():
    bf = _make_bf(max_attempts=3, window_seconds=60)
    assert bf.is_locked("unknown") is False


def test_mark_success_resets():
    bf = _make_bf(max_attempts=3, window_seconds=60, lockout_seconds=120)
    bf.record_failure("user:1")
    bf.record_failure("user:1")
    bf.record_failure("user:1")
    assert bf.is_locked("user:1") is True
    bf.mark_success("user:1")
    assert bf.is_locked("user:1") is False


def test_mark_success_clears_counter():
    bf = _make_bf(max_attempts=3, window_seconds=60, lockout_seconds=120)
    bf.record_failure("user:1")
    bf.record_failure("user:1")
    bf.mark_success("user:1")
    # Counter reset — should need 3 new failures
    bf.record_failure("user:1")
    bf.record_failure("user:1")
    assert bf.is_locked("user:1") is False
    bf.record_failure("user:1")
    assert bf.is_locked("user:1") is True


def test_get_retry_after():
    bf = _make_bf(max_attempts=2, window_seconds=60, lockout_seconds=300)
    assert bf.get_retry_after("user:1") == 0  # not locked
    bf.record_failure("user:1")
    bf.record_failure("user:1")
    assert bf.get_retry_after("user:1") > 0


def test_separate_keys_independent():
    bf = _make_bf(max_attempts=2, window_seconds=60, lockout_seconds=120)
    bf.record_failure("user:A")
    bf.record_failure("user:A")
    assert bf.is_locked("user:A") is True
    assert bf.is_locked("user:B") is False


# ---------------------------------------------------------------------------
# BruteForceProtection — custom backend
# ---------------------------------------------------------------------------


def test_custom_backend():
    backend = MemoryBackend()
    bf = _make_bf(max_attempts=2, window_seconds=60, lockout_seconds=60, backend=backend)
    bf.record_failure("test")
    bf.record_failure("test")
    assert bf.is_locked("test") is True
    # Verify it used our backend
    assert backend.get_sync("bf:test") == 2


# ---------------------------------------------------------------------------
# BruteForceProtection middleware
# ---------------------------------------------------------------------------


def _app_with_brute_force(**kwargs):
    app = Velocix()

    @app.get("/ping")
    async def ping(request):
        return {"ok": True}

    @app.post("/login")
    async def login(request):
        return {"ok": True}

    app.add_middleware(partial(BruteForceProtection, **kwargs))
    return app


def test_middleware_allows_unlocked_requests():
    app = _app_with_brute_force(max_attempts=3, window_seconds=60, lockout_seconds=120)

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/ping")
            assert resp.status_code == 200

    _run(scenario())


def test_middleware_blocks_locked_ip():
    async def scenario():
        from velocix.core.request import Request

        middleware = BruteForceProtection(
            _passthrough_app, max_attempts=2, window_seconds=60, lockout_seconds=120
        )

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/ping",
            "query_string": b"",
            "headers": [],
            "server": ("test", 80),
            "client": ("testclient", 50000),
        }
        request = Request(scope, receive=None)

        # Lock the key directly (this is the same IP TestClient/the request
        # scope above resolves to via the default IP-based key_func)
        middleware.record_failure("testclient")
        middleware.record_failure("testclient")

        resp = await middleware(request)
        assert resp.status_code == 429
        import orjson

        body = orjson.loads(resp.body)
        assert body["error"]["code"] == "BRUTE_FORCE_LOCKED"

    _run(scenario())


def test_middleware_with_custom_key_func():
    app = Velocix()

    @app.get("/ping")
    async def ping(request):
        return {"ok": True}

    def my_key_func(request):
        return "static-key"

    app.add_middleware(partial(
        BruteForceProtection,
        max_attempts=1,
        window_seconds=60,
        lockout_seconds=120,
        key_func=my_key_func,
    ))

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/ping")
            assert resp.status_code == 200

    _run(scenario())
