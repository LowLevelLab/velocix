"""Regression tests for issue #8: route_cache and the depends.py per-handler
caches used to grow without bound (a CachedRoute per distinct concrete
dynamic path, or a cache entry per distinct handler function, forever).
Both now prune themselves on write, mirroring Velocix._prune_response_cache.
"""

from velocix import Router
from velocix.core.depends import (
    _CACHE_MAX_SIZE,
    _plan_cache,
    _sig_cache,
    _type_hints_cache,
    get_plan_and_needs_request,
)


def test_router_dynamic_cache_stays_bounded():
    router = Router()

    def handler(user_id: int):
        return {}

    router.add_route("GET", "/users/{user_id}", handler)

    # Every distinct id is its own concrete path -> its own CachedRoute.
    for user_id in range(router._ROUTE_CACHE_MAX_SIZE + 500):
        router.resolve("GET", f"/users/{user_id}")

    assert len(router.route_cache["GET"]) <= router._ROUTE_CACHE_MAX_SIZE


def test_router_static_cache_unaffected_by_pruning():
    """Static routes are registration-bounded already; pruning shouldn't
    make a normal, small app lose its cached static routes."""
    router = Router()

    def handler():
        return {}

    router.add_route("GET", "/health", handler)
    router.resolve("GET", "/health")
    router.resolve("GET", "/health")
    assert "/health" in router.route_cache["GET"]


def test_depends_caches_stay_bounded():
    # Distinct closures -> distinct id()s -> distinct cache entries.
    handlers = []
    for i in range(_CACHE_MAX_SIZE + 500):
        def handler(x: int = i):
            return x

        handlers.append(handler)

    for handler in handlers:
        get_plan_and_needs_request(handler)

    assert len(_sig_cache) <= _CACHE_MAX_SIZE
    assert len(_type_hints_cache) <= _CACHE_MAX_SIZE
    assert len(_plan_cache) <= _CACHE_MAX_SIZE
