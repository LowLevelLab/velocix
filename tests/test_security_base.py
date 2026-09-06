"""Tests for security base classes.

Covers: SecurityEvent creation/to_dict, Severity levels, MemoryBackend
incr/get/reset (async + sync), and HookManager priority ordering.
"""

import asyncio

from velocix.security.base import (
    HookManager,
    MemoryBackend,
    SecurityEvent,
    Severity,
)


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# SecurityEvent
# ---------------------------------------------------------------------------


def test_security_event_creation():
    event = SecurityEvent(
        event_type="TEST_EVENT",
        severity=Severity.HIGH,
        source_ip="1.2.3.4",
        path="/api/test",
        detail="something happened",
        metadata={"key": "value"},
    )
    assert event.event_type == "TEST_EVENT"
    assert event.severity == Severity.HIGH
    assert event.source_ip == "1.2.3.4"
    assert event.path == "/api/test"
    assert event.detail == "something happened"
    assert event.metadata == {"key": "value"}
    assert isinstance(event.timestamp, float)
    assert event.timestamp > 0


def test_security_event_default_metadata():
    event = SecurityEvent(event_type="X", severity=Severity.LOW)
    assert event.metadata == {}
    assert event.source_ip == ""
    assert event.path == ""
    assert event.detail == ""


def test_security_event_to_dict():
    event = SecurityEvent(
        event_type="RATE_LIMIT_HIT",
        severity=Severity.MEDIUM,
        source_ip="10.0.0.1",
        path="/api/data",
        detail="too many requests",
        metadata={"limit": 100},
    )
    d = event.to_dict()
    assert d["event_type"] == "RATE_LIMIT_HIT"
    assert d["severity"] == "MEDIUM"
    assert d["source_ip"] == "10.0.0.1"
    assert d["path"] == "/api/data"
    assert d["detail"] == "too many requests"
    assert d["metadata"] == {"limit": 100}
    assert "timestamp" in d


def test_security_event_to_dict_empty_metadata():
    event = SecurityEvent(event_type="X", severity=Severity.LOW)
    d = event.to_dict()
    assert "metadata" not in d


def test_severity_ordering():
    assert Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL
    assert Severity.CRITICAL > Severity.HIGH


# ---------------------------------------------------------------------------
# MemoryBackend
# ---------------------------------------------------------------------------


def test_memory_backend_incr_first_call():
    async def scenario():
        backend = MemoryBackend()
        count = await backend.incr("key1", window=60.0)
        assert count == 1

    _run(scenario())


def test_memory_backend_incr_accumulates():
    async def scenario():
        backend = MemoryBackend()
        assert await backend.incr("key1", window=60.0) == 1
        assert await backend.incr("key1", window=60.0) == 2
        assert await backend.incr("key1", window=60.0) == 3

    _run(scenario())


def test_memory_backend_incr_separate_keys():
    async def scenario():
        backend = MemoryBackend()
        assert await backend.incr("a", window=60.0) == 1
        assert await backend.incr("b", window=60.0) == 1
        assert await backend.incr("a", window=60.0) == 2

    _run(scenario())


def test_memory_backend_get_returns_count():
    async def scenario():
        backend = MemoryBackend()
        assert await backend.get("missing") == 0
        await backend.incr("key1", window=60.0)
        await backend.incr("key1", window=60.0)
        assert await backend.get("key1") == 2

    _run(scenario())


def test_memory_backend_get_expired_returns_zero():
    async def scenario():
        backend = MemoryBackend()
        # Use a very short window — it will expire immediately
        await backend.incr("key1", window=0.001)
        # Wait for expiry
        await asyncio.sleep(0.01)
        assert await backend.get("key1") == 0

    _run(scenario())


def test_memory_backend_reset_deletes_key():
    async def scenario():
        backend = MemoryBackend()
        await backend.incr("key1", window=60.0)
        await backend.incr("key1", window=60.0)
        assert await backend.get("key1") == 2
        await backend.reset("key1")
        assert await backend.get("key1") == 0

    _run(scenario())


def test_memory_backend_reset_nonexistent_key():
    async def scenario():
        backend = MemoryBackend()
        # Should not raise
        await backend.reset("nonexistent")
        assert await backend.get("nonexistent") == 0

    _run(scenario())


def test_memory_backend_incr_resets_on_window_expiry():
    async def scenario():
        backend = MemoryBackend()
        await backend.incr("key1", window=0.01)
        await asyncio.sleep(0.02)
        # After window expires, incr should start fresh
        count = await backend.incr("key1", window=60.0)
        assert count == 1

    _run(scenario())


# ---------------------------------------------------------------------------
# HookManager
# ---------------------------------------------------------------------------


def _make_hook(priority=100, response=None):
    """Create a simple hook that returns the given response or None."""
    class SimpleHook:
        def __init__(self, p, r):
            self.priority = p
            self._response = r

        async def on_request(self, request):
            return self._response
    return SimpleHook(priority, response)


def test_hook_manager_no_hooks_passes_through():
    async def scenario():
        from velocix.core.request import Request
        from velocix.core.response import Response

        async def app(request):
            return Response(b"ok", status_code=200)

        manager = HookManager(app, hooks=[])
        scope = {
            "type": "http", "method": "GET", "path": "/",
            "query_string": b"", "headers": [],
            "server": ("test", 80), "client": ("test", 50000),
        }
        request = Request(scope, receive=None)
        resp = await manager(request)
        assert resp.status_code == 200

    _run(scenario())


def test_hook_manager_hooks_run_in_priority_order():
    """Hooks with lower priority run first. If any returns a Response, request is blocked."""
    async def scenario():
        from velocix.core.request import Request
        from velocix.core.response import Response

        call_order = []

        class TrackingHook:
            def __init__(self, p, name):
                self.priority = p
                self._name = name

            async def on_request(self, request):
                call_order.append(self._name)
                return None  # pass through

        async def app(request):
            call_order.append("app")
            return Response(b"ok", status_code=200)

        hooks = [TrackingHook(200, "B"), TrackingHook(100, "A")]
        manager = HookManager(app, hooks=hooks)
        scope = {
            "type": "http", "method": "GET", "path": "/",
            "query_string": b"", "headers": [],
            "server": ("test", 80), "client": ("test", 50000),
        }
        request = Request(scope, receive=None)
        await manager(request)
        assert call_order == ["A", "B", "app"]

    _run(scenario())


def test_hook_manager_blocking_hook_stops_pipeline():
    async def scenario():
        from velocix.core.request import Request
        from velocix.core.response import Response

        class BlockingHook:
            priority = 50

            async def on_request(self, request):
                return Response(b"blocked", status_code=403)

        class PassThroughHook:
            priority = 100

            async def on_request(self, request):
                return None

        async def app(request):
            return Response(b"should not reach", status_code=200)

        manager = HookManager(app, hooks=[PassThroughHook(), BlockingHook()])
        scope = {
            "type": "http", "method": "GET", "path": "/",
            "query_string": b"", "headers": [],
            "server": ("test", 80), "client": ("test", 50000),
        }
        request = Request(scope, receive=None)
        resp = await manager(request)
        assert resp.status_code == 403
        assert resp.body == b"blocked"

    _run(scenario())


def test_hook_manager_add_hook():
    async def scenario():
        from velocix.core.request import Request
        from velocix.core.response import Response

        call_order = []

        class HookA:
            priority = 100
            async def on_request(self, request):
                call_order.append("A")
                return None

        class HookB:
            priority = 50
            async def on_request(self, request):
                call_order.append("B")
                return None

        async def app(request):
            call_order.append("app")
            return Response(b"ok", status_code=200)

        manager = HookManager(app, hooks=[HookA()])
        manager.add_hook(HookB())
        scope = {
            "type": "http", "method": "GET", "path": "/",
            "query_string": b"", "headers": [],
            "server": ("test", 80), "client": ("test", 50000),
        }
        request = Request(scope, receive=None)
        await manager(request)
        # B has priority 50, A has 100 — B runs first
        assert call_order == ["B", "A", "app"]

    _run(scenario())
