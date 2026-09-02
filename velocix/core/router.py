"""
Optimized Velocix Router with caching and advanced routing
"""

import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Optional

from .exceptions import MethodNotAllowed, NotFound


@dataclass
class RouteMetrics:
    """Per-route hit tracking, only attached when Router(metrics_enabled=True)"""

    hit_count: int = 0
    cache_hits: int = 0


@dataclass
class CachedRoute:
    """Cached route with TTL"""

    handler: Callable
    params: dict[str, Any]
    created_at: float = field(default_factory=time.time)
    ttl: float = 300.0  # 5 minutes
    version: int = 0
    metrics: RouteMetrics | None = None

    def is_valid(self) -> bool:
        return time.time() - self.created_at < self.ttl


@dataclass
class RouteNode:
    """Optimized route tree node"""

    handler: Callable | None = None
    children: dict[str, "RouteNode"] = field(default_factory=dict)
    param_child: Optional["RouteNode"] = None
    param_name: str | None = None
    is_endpoint: bool = False
    methods: set[str] = field(default_factory=set)
    constraints: dict[str, Callable] = field(default_factory=dict)


class Router:
    """Ultra-high performance router with advanced caching and optimization"""

    def __init__(self, *, metrics_enabled: bool = False):
        # Per-route metrics (hit counts, avg response time) are opt-in: the
        # counter mutation on every dynamic-route cache hit and the clock
        # reads on first resolve are pure overhead for apps that never call
        # get_metrics(). Instrumentation belongs behind an explicit flag, the
        # same reason Prometheus/OTel middleware is opt-in.
        self.metrics_enabled = metrics_enabled
        self.root = RouteNode()
        self.route_cache: dict[str, dict[str, CachedRoute]] = defaultdict(dict)
        self._routes_version: int = 0
        self.method_trees: dict[str, RouteNode] = {
            "GET": RouteNode(),
            "POST": RouteNode(),
            "PUT": RouteNode(),
            "DELETE": RouteNode(),
            "PATCH": RouteNode(),
            "HEAD": RouteNode(),
            "OPTIONS": RouteNode(),
            "WEBSOCKET": RouteNode(),
        }
        self.static_routes: dict[str, dict[str, Callable]] = defaultdict(dict)
        self.middleware_stack: list[Callable] = []
        # Flat (method, path, handler, name) registration log for include_router
        self._registered: list[tuple[str, str, Callable, str | None]] = []
        # name -> path template for reverse routing (first registration wins)
        self._named_routes: dict[str, str] = {}

    def add_constraint(self, param_name: str, constraint: Callable):
        """Add parameter constraint for validation"""

        def decorator(func):
            if not hasattr(func, "_constraints"):
                func._constraints = {}
            func._constraints[param_name] = constraint
            return func

        return decorator

    def int_constraint(self, value: str) -> bool:
        """Integer parameter constraint"""
        try:
            int(value)
            return True
        except ValueError:
            return False

    def uuid_constraint(self, value: str) -> bool:
        """UUID parameter constraint"""
        import re

        uuid_pattern = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
        return bool(uuid_pattern.match(value))

    def add_route(
        self,
        method: str,
        path: str,
        handler: Callable,
        constraints: dict[str, Callable] | None = None,
        name: str | None = None,
    ):
        """Add route with advanced optimization and validation"""
        # Input validation
        if not method:
            raise ValueError("Method cannot be empty")

        if not isinstance(method, str):
            raise TypeError("Method must be a string")

        if not path:
            raise ValueError("Path cannot be empty")

        if not isinstance(path, str):
            raise TypeError("Path must be a string")

        if not callable(handler):
            raise TypeError("Handler must be callable")

        # Validate HTTP method
        valid_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "WEBSOCKET"}
        if method.upper() not in valid_methods:
            raise ValueError(f"Invalid method: {method}")

        method = method.upper()

        # Normalize path
        if not path.startswith("/"):
            path = "/" + path
        if path != "/" and path.endswith("/"):
            path = path[:-1]

        self._registered.append((method, path, handler, name))
        if name is not None and name not in self._named_routes:
            self._named_routes[name] = path

        # Bump version so cached entries from before this mutation are invalidated
        self._routes_version += 1

        # Check for static route optimization
        if "{" not in path:
            self.static_routes[method][path] = handler
            self.route_cache[method][path] = CachedRoute(handler, {}, version=self._routes_version)
            return

        # Build route tree
        tree = self.method_trees[method]
        current = tree
        parts = [p for p in path.split("/") if p]

        for part in parts:
            if part.startswith("{") and part.endswith("}"):
                # Parameter segment
                param_name = part[1:-1]
                if not current.param_child:
                    current.param_child = RouteNode()
                    current.param_name = param_name
                current = current.param_child

                # Apply constraints
                if constraints and param_name in constraints:
                    current.constraints[param_name] = constraints[param_name]

            else:
                # Static segment
                if part not in current.children:
                    current.children[part] = RouteNode()
                current = current.children[part]

        current.handler = handler
        current.is_endpoint = True
        current.methods.add(method)



    def get(self, path: str, *, name: str | None = None):
        """GET route decorator"""

        def decorator(handler):
            self.add_route("GET", path, handler, name=name)
            return handler

        return decorator

    def post(self, path: str, *, name: str | None = None):
        """POST route decorator"""

        def decorator(handler):
            self.add_route("POST", path, handler, name=name)
            return handler

        return decorator

    def put(self, path: str, *, name: str | None = None):
        """PUT route decorator"""

        def decorator(handler):
            self.add_route("PUT", path, handler, name=name)
            return handler

        return decorator

    def delete(self, path: str, *, name: str | None = None):
        """DELETE route decorator"""

        def decorator(handler):
            self.add_route("DELETE", path, handler, name=name)
            return handler

        return decorator

    def patch(self, path: str, *, name: str | None = None):
        """PATCH route decorator"""

        def decorator(handler):
            self.add_route("PATCH", path, handler, name=name)
            return handler

        return decorator

    def head(self, path: str, *, name: str | None = None):
        """HEAD route decorator"""

        def decorator(handler):
            self.add_route("HEAD", path, handler, name=name)
            return handler

        return decorator

    def options(self, path: str, *, name: str | None = None):
        """OPTIONS route decorator"""

        def decorator(handler):
            self.add_route("OPTIONS", path, handler, name=name)
            return handler

        return decorator

    def websocket(self, path: str, *, name: str | None = None):
        """WebSocket route decorator"""

        def decorator(handler):
            self.add_route("WEBSOCKET", path, handler, name=name)
            return handler

        return decorator

    def include_router(self, router: "Router", prefix: str = "", tags: list[str] | None = None) -> None:
        """Merge another router's routes into this one, optionally under a prefix.

        Args:
            router: Router whose routes should be re-registered here
            prefix: Path prefix prepended to every route (e.g. "/api")
            tags: Tags applied to every route in the router
        """
        prefix = prefix.rstrip("/") if prefix else ""
        for method, path, handler, name in router._registered:
            self.add_route(method, prefix + path, handler, name=name)
            if tags:
                existing = getattr(handler, "__route_tags__", None)
                if existing:
                    handler.__route_tags__ = list(existing) + tags
                else:
                    handler.__route_tags__ = tags

    def url_path_for(self, name: str, /, **path_params: Any) -> str:
        """Build a URL path for a named route (reverse routing).

        Args:
            name: Route name registered via ``name=`` on a route decorator
            **path_params: Values for the route's path placeholders

        Returns:
            Formatted path, e.g. ``/users/42`` for route ``/users/{user_id}``

        Raises:
            NoMatchFound: If no route with the given name exists
        """
        from urllib.parse import quote

        from .exceptions import NoMatchFound

        template = self._named_routes.get(name)
        if template is None:
            raise NoMatchFound(name, path_params)
        return quote(template.format(**path_params))

    def resolve(self, method: str, path: str) -> tuple[Callable, dict[str, str]]:
        """Ultra-fast route resolution with caching"""
        # Check cache first: no key allocation, no clock reads on the hot path.
        # Cached entries are validated against the router's mutation version
        # instead of a wall-clock TTL, which is exact for in-process mutation.
        by_method = self.route_cache.get(method)
        if by_method is not None:
            cached = by_method.get(path)
            if cached is not None and cached.version == self._routes_version:
                    if self.metrics_enabled and cached.metrics is not None:
                        cached.metrics.cache_hits += 1
                    return cached.handler, cached.params

        # Check static routes first (fastest path)
        if method in self.static_routes and path in self.static_routes[method]:
            handler = self.static_routes[method][path]
            self.route_cache[method][path] = CachedRoute(handler, {}, version=self._routes_version)
            return handler, {}

        # Path exists but not for this method
        allowed = self._find_methods(path) - {method}
        if allowed:
            raise MethodNotAllowed(allowed_methods=sorted(allowed))

        # Dynamic route resolution with error handling
        tree = self.method_trees.get(method)
        if not tree:
            raise NotFound(f"Route not found: {path}")

        current = tree
        params = {}

        try:
            parts = [p for p in path.split("/") if p]

            for part in parts:
                if not part:  # Skip empty parts
                    continue

                if part in current.children:
                    current = current.children[part]
                elif current.param_child:
                    # Check constraints with error handling
                    param_name = current.param_name
                    if param_name and param_name in current.param_child.constraints:
                        constraint = current.param_child.constraints[param_name]
                        try:
                            if not constraint(part):
                                raise NotFound(
                                    f"Route constraint failed for parameter '{param_name}': {part}"
                                )
                        except Exception as e:
                            raise NotFound(
                                f"Route constraint error for parameter '{param_name}': {str(e)}"
                            ) from e

                    if param_name:
                        params[param_name] = part
                    current = current.param_child
                elif current is None:
                    raise NotFound("Route not found: invalid path structure")
                else:
                    raise NotFound(f"Route not found: {path}")
        except Exception as e:
            if isinstance(e, NotFound):
                raise
            raise NotFound(f"Route resolution error: {str(e)}") from e

        if current.is_endpoint and method in current.methods:
            route_handler = current.handler
            if route_handler is None:
                raise NotFound(f"Route not found: {path}")
            handler = route_handler

            self.route_cache[method][path] = CachedRoute(
                handler,
                params.copy(),
                version=self._routes_version,
                metrics=RouteMetrics(hit_count=1) if self.metrics_enabled else None,
            )

            return handler, params

        # Path exists but not for this method
        allowed = self._find_methods(path) - {method}
        if allowed:
            raise MethodNotAllowed(allowed_methods=sorted(allowed))

        raise NotFound(f"Route not found: {path}")

    def _find_methods(self, path: str) -> set[str]:
        """Find all methods registered for a path (static or dynamic)"""
        methods: set[str] = set()

        for method, routes in self.static_routes.items():
            if path in routes:
                methods.add(method)

        if methods:
            return methods

        parts = [p for p in path.split("/") if p]

        for method, tree in self.method_trees.items():
            current = tree
            matched = True

            for part in parts:
                if part in current.children:
                    current = current.children[part]
                elif current.param_child:
                    param_name = current.param_name
                    if param_name and param_name in current.param_child.constraints:
                        constraint = current.param_child.constraints[param_name]
                        try:
                            if not constraint(part):
                                matched = False
                                break
                        except Exception:
                            matched = False
                            break
                    current = current.param_child
                else:
                    matched = False
                    break

            if matched and current.is_endpoint:
                methods.add(method)

        return methods

    def add_middleware(self, middleware: Callable):
        """Add middleware to stack"""
        self.middleware_stack.append(middleware)

    def get_metrics(self) -> dict[str, Any]:
        """Get router performance metrics.

        total_routes counts static routes only (dynamic routes are tracked
        per-entry via CachedRoute.metrics once resolved, not by registration
        count). cache_hit_rate is 0 when metrics are disabled or no dynamic
        route has been resolved yet.
        """
        total_hits = 0
        total_cache_hits = 0
        for routes in self.route_cache.values():
            for cached in routes.values():
                if cached.metrics is not None:
                    total_hits += cached.metrics.hit_count
                    total_cache_hits += cached.metrics.cache_hits

        denom = total_hits + total_cache_hits
        return {
            "total_routes": sum(len(routes) for routes in self.static_routes.values()),
            "cache_size": sum(len(routes) for routes in self.route_cache.values()),
            "cache_hit_rate": (total_cache_hits / denom) if denom else 0,
        }

