"""
Dependency injection system with FastAPI/Starlette-inspired patterns.
Provides efficient dependency resolution with caching and async support.
"""

import asyncio
import inspect
import types
from collections.abc import Callable
from typing import Any, Union, get_args, get_origin, get_type_hints

import msgspec
import orjson

from velocix.core.exceptions import HTTPException, ValidationError
from velocix.core.params import Body, Cookie, File, Form, Header, Query
from velocix.http.multipart import UploadFile


# Sentinel for plain params without a signature default
class _NoDefault:
    __slots__ = ()


_NO_DEFAULT = _NoDefault()


def _is_body_type(annotation: Any) -> bool:
    """True if an annotation should be parsed from the request body.

    Body types are msgspec Structs, dict/list/tuple (or unions of those,
    e.g. `OrderIn | None`); scalar types are query parameters instead.
    """
    origin = get_origin(annotation)
    if origin is Union or origin is types.UnionType:
        return any(_is_body_type(arg) for arg in get_args(annotation))
    if origin is not None:
        return origin in (dict, list, tuple)
    if isinstance(annotation, type):
        try:
            if issubclass(annotation, msgspec.Struct):
                return True
            return issubclass(annotation, (dict, list, tuple))
        except TypeError:
            return False
    return False


def _extract_marker(annotation: Any) -> tuple[Any, Any] | None:
    """Return (marker, real_type) if an Annotated[] annotation carries a
    Query/Header/Cookie marker; None otherwise.

    Supports the modern FastAPI style: `q: Annotated[str | None, Query()]`.
    """
    metadata = getattr(annotation, "__metadata__", None)
    if not metadata:
        return None
    for meta in metadata:
        if isinstance(meta, (Query, Header, Cookie, Form, File, Body)):
            return meta, annotation.__origin__
    return None

# Signature cache for performance.
# Entries store the callable itself alongside the cached value: holding a
# strong reference pins the object's id(), so a recycled id() can never
# collide with a live entry (id() of a dead object can be reused by a new
# one after GC). The identity guard re-checks anyway as defense in depth.
_sig_cache: dict[int, tuple[Callable[..., Any], inspect.Signature]] = {}
_type_hints_cache: dict[int, tuple[Callable[..., Any], dict[str, Any]]] = {}
# Precomputed resolution plan per handler:
# (plan, needs_request, cache_ttl, call_mode, status_code, response_model)
# plan: tuple of (param_name, kind, extra)
# kind: "request" | "depends" | "path" ; extra: Depends instance or type hint
# call_mode: 0 = no args, 1 = positional request only, 2 = full kwargs resolution
# status_code/response_model: route-decorator defaults applied to non-Response results
PlanEntry = tuple[
    tuple[tuple[str, str, Any], ...],
    bool,
    float | None,
    int,
    int | None,
    type[Any] | None,
    type | None,
]
_plan_cache: dict[int, tuple[Callable[..., Any], PlanEntry]] = {}


class Depends:
    """
    Dependency marker with caching support (FastAPI pattern).

    Usage:
        async def get_db(request: Request):
            return Database()

        @app.get("/users")
        async def get_users(db: Database = Depends(get_db)):
            return await db.fetch_all()

    Args:
        dependency: Callable that returns the dependency
        use_cache: Whether to cache the result per request (default: True)
    """

    __slots__ = ("dependency", "use_cache", "_is_async")

    def __init__(self, dependency: Callable[..., Any], *, use_cache: bool = True) -> None:
        self.dependency = dependency
        self.use_cache = use_cache
        self._is_async = asyncio.iscoroutinefunction(dependency)

    def __repr__(self) -> str:
        dep_name = getattr(self.dependency, "__name__", repr(self.dependency))
        return f"Depends({dep_name}, use_cache={self.use_cache})"

    @property
    def is_async(self) -> bool:
        """Check if dependency is async"""
        return self._is_async


def _get_signature(func: Callable[..., Any]) -> inspect.Signature:
    """Get cached function signature (entry pins the callable to prevent id reuse)"""
    func_id = id(func)
    entry = _sig_cache.get(func_id)
    if entry is None or entry[0] is not func:
        _sig_cache[func_id] = (func, inspect.signature(func))
        entry = _sig_cache[func_id]
    return entry[1]


def _get_type_hints_cached(func: Callable[..., Any]) -> dict[str, Any]:
    """Get cached type hints (entry pins the callable to prevent id reuse).

    include_extras=True keeps Annotated[] metadata so Query/Header/Cookie
    markers can be extracted from annotations.
    """
    func_id = id(func)
    entry = _type_hints_cache.get(func_id)
    if entry is None or entry[0] is not func:
        try:
            hints = get_type_hints(func, include_extras=True)
        except Exception:
            hints = {}
        _type_hints_cache[func_id] = (func, hints)
        entry = _type_hints_cache[func_id]
    return entry[1]


def get_resolution_plan(handler: Callable[..., Any]) -> tuple[tuple[str, str, Any], ...]:
    """Return the cached per-handler resolution plan (built on first call)."""
    return _build_resolution_plan(handler)


def get_plan_and_needs_request(handler: Callable[..., Any]) -> PlanEntry:
    """One cached lookup returning (plan, needs_request, cache_ttl, call_mode,
    status_code, response_model)."""
    func_id = id(handler)
    entry = _plan_cache.get(func_id)
    if entry is None or entry[0] is not handler:
        _build_resolution_plan(handler)
        entry = _plan_cache[func_id]
    return entry[1]


def _build_resolution_plan(handler: Callable[..., Any]) -> tuple[tuple[str, str, Any], ...]:
    """Precompute the per-handler resolution plan once, then cache it."""
    func_id = id(handler)
    entry = _plan_cache.get(func_id)
    if entry is None or entry[0] is not handler:
        sig = _get_signature(handler)
        type_hints = _get_type_hints_cached(handler)
        plan: list[tuple[str, str, Any]] = []
        for param_name, param in sig.parameters.items():
            # Skip self and cls parameters
            if param_name in ("self", "cls"):
                continue
            annotation = type_hints.get(param_name)
            annotated = _extract_marker(annotation)
            if annotated is not None:
                marker, hint = annotated
            else:
                marker, hint = None, annotation

            # Inject request object
            if param_name == "request":
                plan.append((param_name, "request", None))
            # Handle Depends() marker
            elif isinstance(param.default, Depends):
                plan.append((param_name, "depends", param.default))
            # Query/Header/Cookie/Form/File markers, either as the default
            # (classic style: `q: str | None = Query(None)`) or as Annotated
            # metadata (modern style: `q: Annotated[str | None, Query()] = None`).
            # extra = (marker, type_hint, default, required)
            elif marker is not None or isinstance(
                param.default, (Query, Header, Cookie, Form, File, Body)
            ):
                if marker is None:
                    marker = param.default
                if isinstance(marker, Query):
                    kind = "query"
                elif isinstance(marker, Header):
                    kind = "header"
                elif isinstance(marker, Cookie):
                    kind = "cookie"
                elif isinstance(marker, Form):
                    kind = "form"
                elif isinstance(marker, Body):
                    kind = "body"
                else:
                    kind = "file"
                if annotated is not None:
                    # Annotated style: requiredness from the signature
                    default = (
                        param.default
                        if param.default is not inspect.Parameter.empty
                        else _NO_DEFAULT
                    )
                else:
                    default = marker.default
                required = default is _NO_DEFAULT or default is Ellipsis
                if isinstance(marker, Body):
                    # Normalize Body marker: pre-resolve key at build time
                    plan.append((param_name, kind, (marker.alias or param_name, hint, default, required)))
                else:
                    plan.append((param_name, kind, (marker, hint, default, required)))
            # Plain parameter: a Struct/dict/list annotation is parsed from
            # the request body; otherwise it is a path value if the name is
            # in the route path, or a query parameter (default or required).
            # body extra = (type_hint, required, default)
            # path extra = (type_hint, default) where default is _NO_DEFAULT
            elif _is_body_type(hint):
                required = param.default is inspect.Parameter.empty
                default = (
                    param.default
                    if param.default is not inspect.Parameter.empty
                    else None
                )
                # Normalize: (key, hint, default, required) — key resolved at
                # build time so the per-request path is pure unpacking.
                plan.append((param_name, "body", (param_name, hint, default, required)))
            else:
                default = (
                    param.default
                    if param.default is not inspect.Parameter.empty
                    else _NO_DEFAULT
                )
                plan.append((param_name, "path", (hint, default)))

        # --- multi-body detection ---
        # Count body params to decide whether to embed/wrap.
        body_indices = [i for i, (_, kind, _) in enumerate(plan) if kind == "body"]
        body_count = len(body_indices)
        if body_count > 1:
            plan = list(plan)
            for idx in body_indices:
                old_name, _old_kind, old_extra = plan[idx]
                # old_extra is already (key, hint, default, required)
                plan[idx] = (old_name, "body_multi", old_extra)
            plan = [tuple(p) for p in plan]
        elif body_count == 1:
            idx = body_indices[0]
            old_name, _old_kind, old_extra = plan[idx]
            # Check if Body(embed=True) was explicitly set.
            # After normalization, first elem is always key (str), so we
            # need the original marker.  The Body() marker path stores
            # (marker, hint, default, required) before normalization —
            # but we already normalized.  Instead, check the handler's
            # type hints to find the Body marker.
            hints = _get_type_hints_cached(handler)
            param_hint = hints.get(old_name)
            body_marker = None
            if isinstance(param_hint, type) and isinstance(getattr(param_hint, '__metadata__', None), tuple):
                pass
            elif param_hint is not None and hasattr(param_hint, '__metadata__'):
                for m in param_hint.__metadata__:
                    if isinstance(m, Body):
                        body_marker = m
                        break
            # Also check the signature default
            if body_marker is None:
                sig = _get_signature(handler)
                param_obj = sig.parameters.get(old_name)
                if param_obj is not None and isinstance(param_obj.default, Body):
                    body_marker = param_obj.default
            if body_marker is not None and body_marker.embed is True:
                plan = list(plan)
                plan[idx] = (old_name, "body_embed", old_extra)
                plan = [tuple(p) for p in plan]
        plan_tuple = tuple(plan)
        # Every resolved param either needs the Request (request/depends/query/
        # header/cookie, or a plain param that may fall back to query) — the
        # empty plan is the only request-free case.
        needs_request = bool(plan_tuple)
        cache_ttl = getattr(handler, "__response_cache_ttl__", None)
        status_code = getattr(handler, "__route_status_code__", None)
        response_model = getattr(handler, "__response_model__", None)
        response_class = getattr(handler, "__route_response_class__", None)
        # Fast call modes:
        #   0: no args                    -> handler()
        #   1: single positional request  -> handler(request)
        #   2: path/request only          -> sync kwargs, no coroutine
        #   3: has Depends                -> async resolve_dependencies
        #   4: path/request only          -> positional args (no kwargs dict)
        if not plan_tuple:
            call_mode = 0
        elif (
            len(plan_tuple) == 1
            and plan_tuple[0][1] == "request"
            and sig.parameters.get("request") is not None
            and sig.parameters["request"].kind
            in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        ):
            call_mode = 1
        elif any(kind in ("depends", "body", "body_multi", "body_embed", "form", "file") for _, kind, _ in plan_tuple):
            call_mode = 3
        elif all(kind in ("request", "path") for _, kind, _ in plan_tuple):
            call_mode = 4
        else:
            call_mode = 2
        entry = (
            handler,
            (plan_tuple, needs_request, cache_ttl, call_mode, status_code, response_model, response_class),
        )
        _plan_cache[func_id] = entry
    return entry[1][0]


def _convert_type(raw: str, hint: Any) -> Any:
    """Convert a raw string to the annotated type (lenient on failure)."""
    if hint is None or hint is str:
        return raw
    try:
        if hint is int:
            return int(raw)
        if hint is float:
            return float(raw)
        if hint is bool:
            return raw.lower() in ("true", "1", "yes")
    except (ValueError, AttributeError):
        pass
    return raw


def _resolve_query(request: Any, name: str, extra: tuple[Query, Any, Any, bool]) -> Any:
    """Resolve a Query-marked parameter (marker, hint, default, required)."""
    marker, hint, default, required = extra
    raw = request.query_params.get(marker.alias or name)
    if raw is None:
        if required:
            raise HTTPException(422, f"Missing required query parameter '{name}'")
        return default
    return _convert_type(raw, hint)


def _resolve_header(request: Any, name: str, extra: tuple[Header, Any, Any, bool]) -> Any:
    """Resolve a Header-marked parameter (marker, hint, default, required)."""
    marker, hint, default, required = extra
    header_name = marker.alias or (
        name.replace("_", "-") if marker.convert_underscores else name
    )
    raw = request.headers.get(header_name.lower().encode("latin-1"))
    if raw is None:
        if required:
            raise HTTPException(422, f"Missing required header '{header_name}'")
        return default
    return _convert_type(raw.decode("latin-1"), hint)


def _resolve_cookie(request: Any, name: str, extra: tuple[Cookie, Any, Any, bool]) -> Any:
    """Resolve a Cookie-marked parameter (marker, hint, default, required)."""
    marker, hint, default, required = extra
    raw = request.cookies.get(marker.alias or name)
    if raw is None:
        if required:
            raise HTTPException(422, f"Missing required cookie '{name}'")
        return default
    return _convert_type(raw, hint)


def _resolve_plain(request: Any, name: str, extra: tuple[Any, Any], path_params: dict[str, Any]) -> Any:
    """Resolve a plain parameter: path value if in the route, else query."""
    hint, default = extra
    if name in path_params:
        return _convert_type(path_params[name], hint)
    if request is None:
        raise HTTPException(422, f"Missing required query parameter '{name}'")
    raw = request.query_params.get(name)
    if raw is None:
        if default is _NO_DEFAULT:
            raise HTTPException(422, f"Missing required query parameter '{name}'")
        return default
    return _convert_type(raw, hint)


def resolve_positional(
    request: Any,
    path_params: dict[str, Any] | None,
    plan: tuple[tuple[str, str, Any], ...],
) -> tuple[Any, ...]:
    """Build handler args positionally for plans of only request/path params.

    The plan iterates signature parameters in order, so appending values in
    plan order yields the exact positional argument list. Calling
    ``handler(*args)`` avoids the kwargs dict allocation and the keyword-name
    mapping the callee would otherwise perform (CPython's vectorcall fast
    path); benchmarked ~16% faster than ``handler(**kwargs)`` on small plans.
    """
    if not plan:
        return ()
    args: list[Any] = []
    path_params = path_params or {}
    for param_name, kind, extra in plan:
        if kind == "request":
            args.append(request)
        elif param_name in path_params:
            # Inline the conversion — runs on every request with a path
            # param, so avoid helper call overhead
            hint = extra[0]
            raw = path_params[param_name]
            if hint is int:
                try:
                    args.append(int(raw))
                except (ValueError, AttributeError):
                    args.append(raw)
            elif hint is float:
                try:
                    args.append(float(raw))
                except (ValueError, AttributeError):
                    args.append(raw)
            elif hint is bool:
                args.append(raw.lower() in ("true", "1", "yes"))
            else:
                args.append(raw)
        else:
            # Plain param not in the route path: query fallback
            args.append(_resolve_plain(request, param_name, extra, path_params))
    return tuple(args)


def resolve_kwargs(
    request: Any,
    path_params: dict[str, Any] | None,
    plan: tuple[tuple[str, str, Any], ...],
) -> dict[str, Any]:
    """Build the handler kwargs synchronously for plans without Depends.

    The async resolve_dependencies() wraps this for Depends plans, where the
    coroutine overhead is unavoidable. Path/request/query/header/cookie-only
    plans (the common case) skip the coroutine entirely.
    """
    if not plan:
        return {}
    kwargs: dict[str, Any] = {}
    path_params = path_params or {}
    for param_name, kind, extra in plan:
        # request and plain-path params are the hot cases: check them first so
        # common handlers pay one or two comparisons, not the full marker chain
        if kind == "request":
            kwargs[param_name] = request
        elif kind == "path":
            if param_name in path_params:
                # Inline the conversion — runs on every request with a path
                # param, so avoid helper call overhead
                hint = extra[0]
                raw = path_params[param_name]
                if hint is int:
                    try:
                        kwargs[param_name] = int(raw)
                    except (ValueError, AttributeError):
                        kwargs[param_name] = raw
                elif hint is float:
                    try:
                        kwargs[param_name] = float(raw)
                    except (ValueError, AttributeError):
                        kwargs[param_name] = raw
                elif hint is bool:
                    kwargs[param_name] = raw.lower() in ("true", "1", "yes")
                else:
                    kwargs[param_name] = raw
            else:
                # Plain param not in the route path: query fallback
                kwargs[param_name] = _resolve_plain(request, param_name, extra, path_params)
        elif kind == "query":
            kwargs[param_name] = _resolve_query(request, param_name, extra)
        elif kind == "header":
            kwargs[param_name] = _resolve_header(request, param_name, extra)
        elif kind == "cookie":
            kwargs[param_name] = _resolve_cookie(request, param_name, extra)
    return kwargs


async def resolve_dependencies(
    handler: Callable[..., Any],
    request: Any,
    path_params: dict[str, Any] | None = None,
    plan: tuple[tuple[str, str, Any], ...] | None = None,
) -> dict[str, Any]:
    """
    Resolve dependencies from function signature (FastAPI pattern).

    Supports:
    - Request parameter injection
    - Path parameter injection with type conversion
    - Depends() marker for dependency injection
    - Async and sync dependencies
    - Per-request caching

    The resolution plan is precomputed once per handler, so handlers with no
    parameters (or only "request") skip all per-request signature work.
    Callers with the plan already in hand pass it in to avoid the lookup.

    Args:
        handler: Route handler function
        request: Request object
        path_params: Path parameters from URL
        plan: Precomputed resolution plan (optional)

    Returns:
        Dictionary of resolved dependencies
    """
    plan = _build_resolution_plan(handler) if plan is None else plan
    if not plan:
        return {}

    kwargs: dict[str, Any] = {}
    path_params = path_params or {}
    dep_cache: dict[str, Any] | None = None
    _parsed_body: Any = _NO_DEFAULT

    for param_name, kind, extra in plan:
        # Inject request object
        if kind == "request":
            kwargs[param_name] = request
            continue

        # Handle Depends() marker
        if kind == "depends":
            dep: Depends = extra
            # Initialize dependency cache on request state (lazily)
            if dep_cache is None:
                if not hasattr(request.state, "_depends_cache"):
                    request.state._depends_cache = {}
                dep_cache = request.state._depends_cache
            cache_key = f"_dep_{id(dep.dependency)}"

            # Use cached value if available
            if dep.use_cache and cache_key in dep_cache:
                kwargs[param_name] = dep_cache[cache_key]
            else:
                # Resolve dependency
                if dep.is_async:
                    result = await dep.dependency(request)
                else:
                    result = dep.dependency(request)

                # Cache if enabled
                if dep.use_cache:
                    dep_cache[cache_key] = result

                kwargs[param_name] = result
            continue

        # Query/Header/Cookie-marked parameters
        if kind == "query":
            kwargs[param_name] = _resolve_query(request, param_name, extra)
            continue
        if kind == "header":
            kwargs[param_name] = _resolve_header(request, param_name, extra)
            continue
        if kind == "cookie":
            kwargs[param_name] = _resolve_cookie(request, param_name, extra)
            continue

        # Form-field parameter: parsed from urlencoded or multipart bodies
        if kind == "form":
            marker, hint, default, required = extra
            raw = (await request.form()).get(marker.alias or param_name)
            if raw is None:
                if required:
                    raise HTTPException(
                        422, f"Missing required form field '{param_name}'"
                    )
                kwargs[param_name] = default
            else:
                kwargs[param_name] = _convert_type(raw, hint)
            continue

        # Uploaded-file parameter: parsed from multipart bodies
        if kind == "file":
            marker, hint, default, required = extra
            raw = (await request.form()).get(marker.alias or param_name)
            if isinstance(raw, UploadFile):
                kwargs[param_name] = raw
            elif not required:
                kwargs[param_name] = default
            else:
                raise HTTPException(
                    422,
                    f"Missing required file '{param_name}' (multipart/form-data expected)",
                )
            continue

        # Body parameter: parse the request body as the annotated type.
        # Single unmarked Struct → flat decode (fastest: one Rust call).
        if kind == "body":
            _key, hint, default, required = extra
            body = await request.body()
            if not body:
                if required:
                    raise ValidationError("Request body is required")
                kwargs[param_name] = default
            else:
                try:
                    kwargs[param_name] = msgspec.json.decode(body, type=hint)
                except msgspec.ValidationError as exc:
                    raise ValidationError(
                        "Request body validation failed",
                        errors=[{"type": "validation_error", "msg": str(exc)}],
                    ) from exc
            continue        # Multi-body / embed: parse body once with orjson, extract by name,
        # convert each field with msgspec.convert (no re-encode step).
        # The parsed dict is cached in a local so multiple body_multi/
        # body_embed entries share one parse.
        # Extra is always (key, hint, default, required) — pre-resolved at
        # build time, no branching needed here.
        if kind in ("body_multi", "body_embed"):
            if _parsed_body is _NO_DEFAULT:
                raw_body = await request.body()
                if not raw_body:
                    _parsed_body = {}
                else:
                    _parsed_body = orjson.loads(raw_body)
            key, hint, default, required = extra

            if key not in _parsed_body:
                if required:
                    raise ValidationError(
                        f"Missing required body field '{key}'"
                    )
                kwargs[param_name] = default
            else:
                try:
                    kwargs[param_name] = msgspec.convert(_parsed_body[key], hint)
                except msgspec.ValidationError as exc:
                    raise ValidationError(
                        "Request body validation failed",
                        errors=[{"type": "validation_error", "msg": str(exc)}],
                    ) from exc
            continue

        # Plain parameter: path value if in the route, else query fallback
        kwargs[param_name] = _resolve_plain(request, param_name, extra, path_params)

    return kwargs

