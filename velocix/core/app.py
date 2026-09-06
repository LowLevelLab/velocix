"""
ASGI application with lifespan management
"""

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable, Coroutine
from typing import Any

import msgspec
import xxhash

from velocix.core.depends import (
    get_plan_and_needs_request,
    resolve_dependencies,
    resolve_kwargs,
    resolve_positional,
)
from velocix.core.exceptions import ErrorHandler, HTTPException, NotFound, ValidationError
from velocix.core.middleware import BaseMiddleware, build_middleware_stack
from velocix.core.request import Request
from velocix.core.response import JSONResponse, Response, StreamingResponse
from velocix.core.router import Router

# Type alias for response types
ResponseType = Response | JSONResponse | StreamingResponse

logger = logging.getLogger("velocix")


class State:
    """Application state container"""

    pass


def cache_response(ttl: float = 60.0) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Cache a route's serialized JSON response body for `ttl` seconds.

    The cached value is the orjson-serialized body (the most expensive part
    of a JSON response), keyed by method + path + query string. Only safe for
    handlers whose output does not depend on per-request state (auth, headers,
    cookies); opt-in per route.

    Cached responses also carry an ETag (xxh64 of the body) and a
    Cache-Control header. Requests with a matching If-None-Match (GET/HEAD)
    are answered with 304 Not Modified and an empty body.

    Usage:
        @app.get("/items")
        @cache_response(ttl=60)
        async def items(request):
            return {"items": ITEMS}
    """

    def decorator(handler: Callable[..., Any]) -> Callable[..., Any]:
        handler.__response_cache_ttl__ = ttl  # type: ignore[attr-defined]
        return handler

    return decorator


def _make_etag(body: bytes) -> bytes:
    """Strong ETag for a serialized body: quoted xxh64 hex digest."""
    return b'"' + xxhash.xxh64(body).hexdigest().encode("ascii") + b'"'


def _if_none_match_matches(header: bytes, etag: bytes) -> bool:
    """Strong comparison of an If-None-Match header against one ETag.

    Handles comma-separated lists and the wildcard `*` (RFC 9110).
    """
    for candidate in header.split(b","):
        candidate = candidate.strip()
        if candidate == b"*" or candidate == etag:
            return True
    return False


def _request_if_none_match(
    request: "Request | None", scope: dict[str, Any] | None
) -> bytes | None:
    """Read the If-None-Match header from a Request or raw scope headers."""
    if request is not None:
        return request.headers.get(b"if-none-match")
    if scope is not None:
        for k, v in scope.get("headers", []):
            if k == b"if-none-match":
                return v
    return None


class Velocix:
    """Main ASGI application with cached middleware compilation"""

    _CACHE_MAX_SIZE: int = 1024

    __slots__ = (
        "router",
        "state",
        "_middleware_stack",
        "_exception_handlers",
        "_error_handler",
        "_startup_handlers",
        "_shutdown_handlers",
        "_background_tasks",
        "_compiled_middleware",
        "_startup_complete",
        "_response_cache",
        "_mounts",
        "title",
        "version",
        "description",
        "docs_url",
        "redoc_url",
        "openapi_url",
        "docs_auth",
        "openapi_schema",
        "tags",
    )

    def __init__(
        self,
        *,
        title: str = "Velocix",
        version: str = "0.1.0",
        description: str = "",
        debug: bool = False,
        docs_url: str | None = "/docs",
        redoc_url: str | None = "/redoc",
        openapi_url: str | None = "/openapi.json",
        docs_auth: Callable[..., Any] | None = None,
        tags: list[dict[str, str]] | None = None,
    ) -> None:
        self.router = Router()
        self.state = State()
        self._middleware_stack: list[type[BaseMiddleware] | Callable[..., Any]] = []
        self._exception_handlers: dict[type[Exception], Any] = {}
        self._startup_handlers: list[Any] = []
        self._shutdown_handlers: list[Any] = []
        self._background_tasks: set[Any] = set()
        self._compiled_middleware: Any = None
        self._startup_complete: bool = False
        self._response_cache: dict[str, tuple[float, bytes, int, bytes | None]] = {}
        self._mounts: dict[str, Any] = {}
        self._error_handler = ErrorHandler(debug=debug)
        self.title = title
        self.version = version
        self.description = description
        self.docs_url = docs_url
        self.redoc_url = redoc_url
        self.openapi_url = openapi_url
        self.docs_auth = docs_auth
        self.tags = tags or []
        self.openapi_schema: dict[str, Any] | None = None

        self._setup_default_exception_handlers()
        self._setup_docs_routes()

    def route(
        self,
        path: str,
        methods: set[str] | None = None,
        *,
        status_code: int | None = None,
        response_model: type[Any] | None = None,
        tags: list[str] | None = None,
        summary: str | None = None,
        description: str | None = None,
        deprecated: bool = False,
        include_in_schema: bool = True,
        operation_id: str | None = None,
        name: str | None = None,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """
        Decorator for adding routes.

        Args:
            path: URL path
            methods: HTTP methods to register
            status_code: Default status for non-Response handler returns
            response_model: msgspec Struct used to validate/filter dict returns
            tags: OpenAPI tags for grouping in docs
            summary: Short summary shown in OpenAPI docs
            description: Verbose description shown in OpenAPI docs
            deprecated: Mark route as deprecated in OpenAPI docs
            include_in_schema: Whether to include this route in OpenAPI schema
            operation_id: Custom OpenAPI operation ID
            name: Route name for reverse routing via ``request.url_for()``
        """

        def decorator(handler: Callable[..., Any]) -> Callable[..., Any]:
            methods_set = methods or {"GET"}
            for method in methods_set:
                self.router.add_route(method, path, handler, name=name)
            if status_code is not None:
                handler.__route_status_code__ = status_code  # type: ignore[attr-defined]
            if response_model is not None:
                handler.__response_model__ = response_model  # type: ignore[attr-defined]
            if tags is not None:
                handler.__route_tags__ = tags  # type: ignore[attr-defined]
            if summary is not None:
                handler.__route_summary__ = summary  # type: ignore[attr-defined]
            if description is not None:
                handler.__route_description__ = description  # type: ignore[attr-defined]
            if deprecated:
                handler.__route_deprecated__ = True  # type: ignore[attr-defined]
            if not include_in_schema:
                handler.__route_include_in_schema__ = False  # type: ignore[attr-defined]
            if operation_id is not None:
                handler.__route_operation_id__ = operation_id  # type: ignore[attr-defined]
            return handler

        return decorator

    def get(
        self,
        path: str,
        *,
        status_code: int | None = None,
        response_model: type[Any] | None = None,
        tags: list[str] | None = None,
        summary: str | None = None,
        description: str | None = None,
        deprecated: bool = False,
        include_in_schema: bool = True,
        operation_id: str | None = None,
        name: str | None = None,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator for GET routes"""
        return self.route(
            path, {"GET"}, status_code=status_code, response_model=response_model,
            tags=tags, summary=summary, description=description, deprecated=deprecated,
            include_in_schema=include_in_schema, operation_id=operation_id, name=name
        )

    def post(
        self,
        path: str,
        *,
        status_code: int | None = None,
        response_model: type[Any] | None = None,
        tags: list[str] | None = None,
        summary: str | None = None,
        description: str | None = None,
        deprecated: bool = False,
        include_in_schema: bool = True,
        operation_id: str | None = None,
        name: str | None = None,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator for POST routes"""
        return self.route(
            path, {"POST"}, status_code=status_code, response_model=response_model,
            tags=tags, summary=summary, description=description, deprecated=deprecated,
            include_in_schema=include_in_schema, operation_id=operation_id, name=name
        )

    def put(
        self,
        path: str,
        *,
        status_code: int | None = None,
        response_model: type[Any] | None = None,
        tags: list[str] | None = None,
        summary: str | None = None,
        description: str | None = None,
        deprecated: bool = False,
        include_in_schema: bool = True,
        operation_id: str | None = None,
        name: str | None = None,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator for PUT routes"""
        return self.route(
            path, {"PUT"}, status_code=status_code, response_model=response_model,
            tags=tags, summary=summary, description=description, deprecated=deprecated,
            include_in_schema=include_in_schema, operation_id=operation_id, name=name
        )

    def delete(
        self,
        path: str,
        *,
        status_code: int | None = None,
        response_model: type[Any] | None = None,
        tags: list[str] | None = None,
        summary: str | None = None,
        description: str | None = None,
        deprecated: bool = False,
        include_in_schema: bool = True,
        operation_id: str | None = None,
        name: str | None = None,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator for DELETE routes"""
        return self.route(
            path, {"DELETE"}, status_code=status_code, response_model=response_model,
            tags=tags, summary=summary, description=description, deprecated=deprecated,
            include_in_schema=include_in_schema, operation_id=operation_id, name=name
        )

    def patch(
        self,
        path: str,
        *,
        status_code: int | None = None,
        response_model: type[Any] | None = None,
        tags: list[str] | None = None,
        summary: str | None = None,
        description: str | None = None,
        deprecated: bool = False,
        include_in_schema: bool = True,
        operation_id: str | None = None,
        name: str | None = None,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator for PATCH routes"""
        return self.route(
            path, {"PATCH"}, status_code=status_code, response_model=response_model,
            tags=tags, summary=summary, description=description, deprecated=deprecated,
            include_in_schema=include_in_schema, operation_id=operation_id, name=name
        )

    def websocket(
        self, path: str, *, name: str | None = None
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator for WebSocket routes"""
        return self.route(path, {"WEBSOCKET"}, name=name)

    def add_middleware(self, middleware_class: type[BaseMiddleware] | Callable[..., Any]) -> None:
        """Add middleware to stack"""
        self._middleware_stack.append(middleware_class)

    def include_router(self, router: Router, prefix: str = "", tags: list[str] | None = None) -> None:
        """Merge another router's routes into this app, optionally under a prefix.

        Args:
            router: Router whose routes should be registered on this app
            prefix: Path prefix prepended to every route (e.g. "/api")
            tags: Tags applied to every route in the router
        """
        self.router.include_router(router, prefix=prefix, tags=tags)

    def mount(self, path: str, app: Any) -> None:
        """Mount an ASGI application under a path prefix.

        Args:
            path: Mount prefix (e.g. "/static")
            app: ASGI callable (e.g. StaticFiles(directory=...))
        """
        path = path.rstrip("/") or "/"
        self._mounts[path] = app

    def add_exception_handler(
        self,
        exc_class: type[Exception],
        handler: Callable[[Request, Exception], Awaitable[ResponseType]],
    ) -> None:
        """Register exception handler"""
        self._exception_handlers[exc_class] = handler

    def on_startup(self, func: Callable[[], Awaitable[None]]) -> Callable[[], Awaitable[None]]:
        """Register startup handler"""
        self._startup_handlers.append(func)
        return func

    def on_shutdown(self, func: Callable[[], Awaitable[None]]) -> Callable[[], Awaitable[None]]:
        """Register shutdown handler"""
        self._shutdown_handlers.append(func)
        return func

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        """ASGI entry point"""
        if scope["type"] == "lifespan":
            await self._handle_lifespan(scope, receive, send)
        elif scope["type"] == "http":
            await self._handle_http(scope, receive, send)
        elif scope["type"] == "websocket":
            await self._handle_websocket(scope, receive, send)

    async def _handle_lifespan(
        self,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        """Handle ASGI lifespan events"""
        while True:
            message = await receive()

            if message["type"] == "lifespan.startup":
                try:
                    for handler in self._startup_handlers:
                        result = handler()
                        if asyncio.iscoroutine(result):
                            await result
                    self._startup_complete = True
                    await send({"type": "lifespan.startup.complete"})
                except Exception as exc:
                    logger.exception("Startup failed")
                    await send({"type": "lifespan.startup.failed", "message": str(exc)})

            elif message["type"] == "lifespan.shutdown":
                try:
                    self._startup_complete = False
                    for task in self._background_tasks:
                        task.cancel()

                    await asyncio.gather(*self._background_tasks, return_exceptions=True)

                    for handler in self._shutdown_handlers:
                        result = handler()
                        if asyncio.iscoroutine(result):
                            await result

                    await send({"type": "lifespan.shutdown.complete"})
                except Exception as exc:
                    logger.exception("Shutdown failed")
                    await send({"type": "lifespan.shutdown.failed", "message": str(exc)})
                break

    async def _handle_http(
        self,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        """Handle HTTP request"""
        # Mounted ASGI apps own their response cycle entirely: dispatch before
        # route resolution, with the mount prefix stripped from a copied scope.
        # Empty dict is falsy, so apps without mounts pay a single attribute
        # read and nothing else.
        if self._mounts:
            path = scope["path"]
            for mount_path, mount_app in self._mounts.items():
                if mount_path == "/" or path == mount_path or path.startswith(
                    mount_path + "/"
                ):
                    if mount_path != "/":
                        child_scope = dict(scope)
                        child_scope["path"] = path[len(mount_path) :] or "/"
                    else:
                        child_scope = scope
                    await mount_app(child_scope, receive, send)
                    return

        request: Request | None = None
        try:
            handler, path_params = self.router.resolve(scope["method"], scope["path"])
            if handler is None:
                raise NotFound(f"Route not found: {scope['path']}")
            response = await self._process_request(scope, receive, handler, path_params)
        except Exception as exc:
            if request is None:
                request = Request(scope, receive)
                request.app = self
            response = await self._handle_exception(request, exc)

        await self._send_response(response, send)

    async def _handle_websocket(
        self,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        """Handle WebSocket connection"""
        from velocix.websocket.connection import WebSocket

        ws = WebSocket(scope, receive, send)

        try:
            handler, path_params = self.router.resolve("WEBSOCKET", ws.path)
        except Exception:
            handler, path_params = None, {}

        if handler is None:
            await send({"type": "websocket.close", "code": 1000})
            return

        ws.path_params = path_params

        try:
            await handler(ws)
        except Exception:
            logger.exception("WebSocket handler error")
            try:
                await ws.close(1011)
            except Exception:
                pass

    async def _process_request(
        self,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
        handler: Callable[..., Any],
        path_params: dict[str, Any],
    ) -> ResponseType:
        """Process HTTP request with error handling and middleware"""
        request: Request | None = None
        try:
            if self._middleware_stack:
                if self._compiled_middleware is None:
                    self._compiled_middleware = build_middleware_stack(
                        self._execute_handler, self._middleware_stack
                    )

                # One plan lookup per request, stashed on the Request so the
                # middleware terminal re-reads it without another lookup.
                entry = get_plan_and_needs_request(handler)
                request = self._init_request(scope, receive, handler, path_params)
                request._plan = entry
                response = await self._compiled_middleware(request)
                # Middleware should return ResponseType, but type system sees Any
                if isinstance(response, (Response, JSONResponse, StreamingResponse)):
                    return response
                return JSONResponse(
                    {"error": "Invalid response type from middleware"}, status_code=500
                )

            # No middleware: pass everything explicitly so _execute_handler
            # never re-reads handler/plan/path_params off the Request.
            (
                plan,
                needs_request,
                cache_ttl,
                call_mode,
                status_code,
                response_model,
                response_class,
            ) = get_plan_and_needs_request(handler)
            if needs_request:
                request = self._init_request(scope, receive, handler, path_params)
                return await self._execute_handler(
                    request,
                    scope,
                    handler,
                    path_params,
                    plan,
                    cache_ttl,
                    call_mode,
                    status_code,
                    response_model,
                    response_class,
                )
            return await self._execute_handler(
                None,
                scope,
                handler,
                path_params,
                plan,
                cache_ttl,
                call_mode,
                status_code,
                response_model,
                response_class,
            )

        except Exception as exc:
            if request is None:
                request = Request(scope, receive)
                request.app = self
            return await self._handle_exception(request, exc)

    def _init_request(
        self,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
        handler: Callable[..., Any],
        path_params: dict[str, Any],
    ) -> Request:
        """Build a Request and attach the resolved handler/params"""
        request = Request(scope, receive)
        request.app = self
        request.path_params = path_params
        request._handler = handler
        return request

    async def _execute_handler(
        self,
        request: Request | None,
        scope: dict[str, Any] | None = None,
        handler: Callable[..., Any] | None = None,
        path_params: dict[str, Any] | None = None,
        plan: tuple[tuple[str, str, Any], ...] | None = None,
        cache_ttl: float | None = None,
        call_mode: int = 2,
        status_code: int | None = None,
        response_model: type[Any] | None = None,
        response_class: type[Response] | None = None,
    ) -> ResponseType:
        """Execute route handler with dependency injection"""
        if handler is None:
            # Called through the middleware stack with a real Request
            handler = request._handler  # type: ignore[union-attr]
            if handler is None:
                # Fallback for handlers invoked outside the normal request path
                handler, _ = self.router.resolve(request.method, request.path)  # type: ignore[union-attr]
                if handler is None:
                    raise NotFound()
            path_params = request.path_params  # type: ignore[union-attr]

        if plan is None:
            entry = getattr(request, "_plan", None) if request is not None else None
            if entry is None:
                entry = get_plan_and_needs_request(handler)
            plan, _, cache_ttl, call_mode, status_code, response_model, response_class = entry

        # Response cache hit: reuse the serialized body, skip handler + orjson.
        # method/path/query are only needed to build the cache key, so defer
        # extracting them until we know the route is actually cached.
        if cache_ttl is not None:
            if request is not None:
                method = request.method
                path = request.path
                query_string = request.query_string
            else:
                assert scope is not None
                method = scope["method"]
                path = scope["path"]
                query_string = scope["query_string"]
            cache_key = f"{method}:{path}?{query_string.decode('latin-1')}"
            cached = self._response_cache.get(cache_key)
            if cached is not None and cached[0] > time.time():
                etag = cached[3]
                remaining = max(int(cached[0] - time.time()), 0)
                inm = _request_if_none_match(request, scope)
                if (
                    etag is not None
                    and method in ("GET", "HEAD")
                    and inm is not None
                    and _if_none_match_matches(inm, etag)
                ):
                    not_modified = Response(
                        b"",
                        status_code=304,
                        headers={
                            "etag": etag.decode("latin-1"),
                            "cache-control": f"public, max-age={remaining}",
                        },
                    )
                    # 304 has no body: drop the auto-added content-type header
                    not_modified.raw_headers = [
                        (k, v) for k, v in not_modified.raw_headers if k != b"content-type"
                    ]
                    return not_modified
                return JSONResponse.from_body(
                    cached[1],
                    cached[2],
                    etag=etag,
                    cache_control=f"public, max-age={remaining}",
                )

        if call_mode == 1:
            result = await handler(request)
        elif call_mode == 0:
            result = await handler()
        elif call_mode == 4:
            # Positional dispatch: plan order == signature order, so building
            # a tuple and splatting avoids the kwargs dict allocation + the
            # callee's keyword-name mapping (vectorcall fast path).
            args = resolve_positional(request, path_params, plan)
            result = await handler(*args)
        elif call_mode == 2:
            kwargs = resolve_kwargs(request, path_params, plan)
            result = await handler(**kwargs)
        else:
            kwargs = await resolve_dependencies(handler, request, path_params, plan)
            result = await handler(**kwargs)

        # dict is the common case (JSON handlers), so check it first; JSONResponse
        # subclasses Response, so a single Response check covers both.
        # status_code/response_model are route-decorator defaults; an explicit
        # Response return always wins (its own status/body are authoritative).
        response: ResponseType
        resp_class = response_class or JSONResponse
        if isinstance(result, dict):
            if response_model is not None:
                try:
                    converted = msgspec.convert(result, type=response_model)
                except msgspec.ValidationError as exc:
                    raise ValidationError(
                        detail="Response validation failed",
                        errors=[{"type": "response_error", "msg": str(exc)}],
                    ) from exc
                if resp_class is JSONResponse:
                    response = JSONResponse.from_body(
                        msgspec.json.encode(converted), status_code=status_code or 200
                    )
                else:
                    response = resp_class(converted, status_code=status_code or 200)
            else:
                response = resp_class(result, status_code=status_code or 200)
        elif isinstance(result, Response):
            response = result
        elif isinstance(result, StreamingResponse):
            response = result
        elif isinstance(result, str):
            if response_class is not None:
                response = response_class(result, status_code=status_code or 200)
            else:
                response = Response(result, media_type="text/plain", status_code=status_code or 200)
        elif result is None:
            response = Response(b"", status_code=status_code or 204)
        else:
            if response_model is not None:
                try:
                    converted = msgspec.convert(result, type=response_model)
                except msgspec.ValidationError as exc:
                    raise ValidationError(
                        detail="Response validation failed",
                        errors=[{"type": "response_error", "msg": str(exc)}],
                    ) from exc
                if resp_class is JSONResponse:
                    response = JSONResponse.from_body(
                        msgspec.json.encode(converted), status_code=status_code or 200
                    )
                else:
                    response = resp_class(converted, status_code=status_code or 200)
            else:
                response = resp_class(result, status_code=status_code or 200)

        # Cache the serialized body only for dict/JSON responses. Compute the
        # ETag once at store time (xxh64 of the exact bytes) so hits never
        # re-hash; the served response carries etag + cache-control so clients
        # can send conditional requests.
        if cache_ttl is not None and isinstance(response, JSONResponse):
            body = bytes(response.body)
            etag = _make_etag(body)
            self._prune_response_cache()
            self._response_cache[cache_key] = (
                time.time() + cache_ttl,
                body,
                response.status_code,
                etag,
            )
            response.raw_headers.append((b"etag", etag))
            response.raw_headers.append(
                (b"cache-control", f"public, max-age={int(cache_ttl)}".encode("latin-1"))
            )

        return response

    def _prune_response_cache(self) -> None:
        """Evict expired entries first, then oldest entries if still over size.

        Pattern from Pallets/cachelib SimpleCache._prune: sweep expired,
        then sort remaining by expiry and drop oldest until under threshold.
        """
        cache = self._response_cache
        if len(cache) <= self._CACHE_MAX_SIZE:
            return
        now = time.time()
        expired = [k for k, v in cache.items() if v[0] < now]
        for k in expired:
            del cache[k]
        if len(cache) <= self._CACHE_MAX_SIZE:
            return
        oldest = sorted(cache, key=lambda k: cache[k][0])
        for k in oldest[: len(cache) - self._CACHE_MAX_SIZE]:
            del cache[k]

    async def _handle_exception(self, request: Request, exc: Exception) -> ResponseType:
        """Handle exceptions with registered handlers"""
        # Handle HTTPException first
        if isinstance(exc, HTTPException):
            return JSONResponse(
                exc.to_dict(), status_code=exc.status_code, headers=exc.headers or None
            )

        # Check custom handlers
        for exc_class, handler in self._exception_handlers.items():
            if isinstance(exc, exc_class):
                result = await handler(request, exc)
                if isinstance(result, (Response, JSONResponse, StreamingResponse)):
                    return result
                else:
                    return JSONResponse(
                        {"error": "Invalid response from exception handler"}, status_code=500
                    )

        # Log unhandled exceptions
        logger.exception("Unhandled exception")
        return JSONResponse({"error": "Internal server error"}, status_code=500)

    async def _send_response(
        self,
        response: Response | StreamingResponse,
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        """Send response to ASGI server"""
        if isinstance(response, StreamingResponse):
            await send(
                {
                    "type": "http.response.start",
                    "status": response.status_code,
                    "headers": response.asgi_headers(),
                }
            )

            content_iterator = response.content
            if callable(content_iterator):
                content_iterator = content_iterator()

            async for chunk in content_iterator:
                await send(
                    {
                        "type": "http.response.body",
                        "body": chunk,
                        "more_body": True,
                    }
                )

            await send(
                {
                    "type": "http.response.body",
                    "body": b"",
                    "more_body": False,
                }
            )
        else:
            await send(
                {
                    "type": "http.response.start",
                    "status": response.status_code,
                    "headers": response.asgi_headers(),
                }
            )

            await send(
                {
                    "type": "http.response.body",
                    "body": response.body,
                    "more_body": False,
                }
            )

        # Run the response's background task after the body is fully sent.
        # Exceptions are logged, never propagated: the response is already
        # on the wire and there is nothing left to send.
        background = response.background
        if background is not None:
            try:
                await background()
            except Exception:
                logger.exception("Background task failed")

    def _setup_default_exception_handlers(self) -> None:
        """Setup default exception handlers"""
        pass

    def _setup_docs_routes(self) -> None:
        """Register /openapi.json, /docs, /redoc routes. Skipped when URLs are None."""
        import html as _html

        from velocix.core.response import HTMLResponse

        title_esc = _html.escape(self.title)

        if self.openapi_url:

            async def openapi_handler(request: Request) -> Response:
                if self.openapi_schema is None:
                    from velocix.openapi.auto_docs import (
                        generate_operation_from_function,
                    )
                    from velocix.openapi.models import (
                        Info,
                        OpenAPISpec,
                        PathItem,
                        Server,
                    )

                    paths: dict[str, PathItem] = {}
                    # Collects every msgspec Struct schema referenced by a request
                    # body's "$ref" (rewritten to "#/components/schemas/..."), so
                    # it can be published under components.schemas below instead
                    # of leaving those refs dangling.
                    schema_registry: dict[str, Any] = {}
                    # router._registered is the flat (method, path, handler, name)
                    # log every add_route() call appends to, so it's the only
                    # source with every route's original template path (e.g.
                    # "/posts/{post_id}") regardless of whether it's been hit
                    # yet. static_routes/route_cache were the wrong source for
                    # this: route_cache is a resolution cache keyed by the
                    # *concrete* request path ("/posts/5"), not the template,
                    # and it's empty for a dynamic route until something
                    # actually resolves it — so dynamic routes were either
                    # missing from the docs entirely or, once hit, showed up
                    # under the literal ID that happened to hit them first.
                    for method, path, handler, _name in self.router._registered:
                        if getattr(handler, "__route_include_in_schema__", True) is False:
                            continue
                        if path in (self.openapi_url, self.docs_url, self.redoc_url):
                            continue
                        op = generate_operation_from_function(
                            handler, path, method.upper(), schema_registry=schema_registry
                        )
                        if path not in paths:
                            paths[path] = PathItem()
                        setattr(paths[path], method.lower(), op)

                    from velocix.openapi.models import Tag

                    tag_objects = [Tag(name=t["name"], description=t.get("description")) for t in self.tags] if self.tags else None

                    components = {"schemas": schema_registry} if schema_registry else None

                    self.openapi_schema = OpenAPISpec(
                        openapi="3.1.0",
                        components=components,
                        info=Info(title=self.title, version=self.version, description=self.description),
                        servers=[Server(url="/", description="Default server")],
                        paths=paths,
                        tags=tag_objects,
                    ).to_dict()
                return JSONResponse(self.openapi_schema)

            self.router.add_route("GET", self.openapi_url, openapi_handler)

        if self.openapi_url and self.docs_url:

            async def swagger_handler(request: Request) -> HTMLResponse:
                openapi_url = self.openapi_url
                from velocix.openapi.generator import (
                    SWAGGER_CSS_SRI,
                    SWAGGER_CSS_URL,
                    SWAGGER_JS_SRI,
                    SWAGGER_JS_URL,
                    SWAGGER_PRESET_SRI,
                    SWAGGER_PRESET_URL,
                )

                js_integrity = f' integrity="{SWAGGER_JS_SRI}" crossorigin="anonymous"' if SWAGGER_JS_SRI else ""
                css_integrity = f' integrity="{SWAGGER_CSS_SRI}" crossorigin="anonymous"' if SWAGGER_CSS_SRI else ""
                preset_integrity = (
                    f' integrity="{SWAGGER_PRESET_SRI}" crossorigin="anonymous"'
                    if SWAGGER_PRESET_SRI
                    else ""
                )
                html_content = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="stylesheet" type="text/css" href="{SWAGGER_CSS_URL}"{css_integrity} />
<title>{title_esc} - Swagger UI</title>
</head>
<body>
<div id="swagger-ui"></div>
<script src="{SWAGGER_JS_URL}"{js_integrity}></script>
<script src="{SWAGGER_PRESET_URL}"{preset_integrity}></script>
<script>
const ui = SwaggerUIBundle({{
    url: '{_html.escape(openapi_url)}',
    dom_id: '#swagger-ui',
    deepLinking: true,
    presets: [
        SwaggerUIBundle.presets.apis,
        SwaggerUIStandalonePreset
    ],
    layout: "StandaloneLayout"
}});
</script>
</body>
</html>"""
                return HTMLResponse(html_content)

            self.router.add_route("GET", self.docs_url, swagger_handler)

        if self.openapi_url and self.redoc_url:

            async def redoc_handler(request: Request) -> HTMLResponse:
                from velocix.openapi.generator import REDOC_JS_SRI, REDOC_JS_URL

                js_integrity = f' integrity="{REDOC_JS_SRI}" crossorigin="anonymous"' if REDOC_JS_SRI else ""
                html_content = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title_esc} - ReDoc</title>
<link href="https://fonts.googleapis.com/css?family=Montserrat:300,400,700|Roboto:300,400,700" rel="stylesheet">
<style>body {{ margin:0; padding:0; }}</style>
</head>
<body>
<redoc spec-url="{_html.escape(self.openapi_url)}"></redoc>
<script src="{REDOC_JS_URL}"{js_integrity}></script>
</body>
</html>"""
                return HTMLResponse(html_content)

            self.router.add_route("GET", self.redoc_url, redoc_handler)

    def add_background_task(self, coro: Coroutine[Any, Any, None]) -> None:
        """Schedule background task"""
        task = asyncio.create_task(coro)
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)
