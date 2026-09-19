# API Simplification: Additive Sugar Layer — Design

## Context

Velocix's core request/response/DI pipeline is already FastAPI-shaped
(`Query`/`Header`/`Cookie`/`Body`/`Form`/`File` markers, `Depends`, msgspec
Structs, `@app.get`/`@app.post` decorators). The friction isn't in that core
API — it's in everything around it: wiring up middleware requires
`functools.partial`, common security features require knowing exact class
names and import paths across three different `velocix.security.*` modules,
and some useful types aren't exported from the top-level `velocix` package.

This project is purely additive. Nothing existing is renamed, removed, or
changed in behavior — confirmed duplicates found during investigation
(`velocix.core.middleware.CORSMiddleware` vs `velocix.security.cors.CORSMiddleware`;
three overlapping OpenAPI/docs pipelines in `velocix/openapi/`;
`velocix.validation.Struct` being a bare `msgspec.Struct` alias) are
explicitly **out of scope** and left untouched. The goal is to make the
common path shorter and more discoverable without touching what already
works, so no existing app can break.

## Goals

- Registering middleware with configuration should not require importing
  `functools.partial`.
- The most common security/middleware setups (CORS, CSRF, sessions, rate
  limiting, gzip, trusted hosts) should be a single method call on `Velocix`
  with no need to know the underlying class name or its module path.
- Everything a typical app needs should import from `velocix` directly.
- The README and shipped example should demonstrate this simplified path,
  since they're a new dev's first impression.

## Non-goals

- No changes to the DI/marker system (`Query`, `Depends`, etc.) — it already
  matches FastAPI's ergonomics.
- No deletion or deprecation of any existing class, module, or import path.
- No new top-level entry point / app class — `Velocix` remains the only
  front door.

## Component 1: `add_middleware` accepts config directly

**File:** `velocix/core/app.py`

Current signature only accepts a bare class or an already-built callable
(typically produced with `functools.partial`):

```python
def add_middleware(self, middleware_class: type[BaseMiddleware] | Callable[..., Any]) -> None:
    self._middleware_stack.append(middleware_class)
```

New signature accepts optional `*args, **kwargs` and wraps with
`functools.partial` internally when either is given:

```python
def add_middleware(
    self,
    middleware_class: type[BaseMiddleware] | Callable[..., Any],
    *args: Any,
    **kwargs: Any,
) -> None:
    """Add middleware to the stack.

    Extra positional/keyword args are bound to the middleware's constructor
    (after `app`), so config no longer requires `functools.partial`:

        app.add_middleware(CORSMiddleware, allow_origins=["https://example.com"])

    A bare class or an already-partial'd callable still works unchanged.
    """
    if args or kwargs:
        middleware_class = partial(middleware_class, *args, **kwargs)
    self._middleware_stack.append(middleware_class)
```

Requires adding `from functools import partial` to `velocix/core/app.py`'s
imports (not currently imported there — only `velocix/core/middleware.py`
and `velocix/__init__.py` import it today).

`build_middleware_stack` in `velocix/core/middleware.py` needs no change —
it already calls `middleware_class(app)`, and a `partial` object called with
one positional arg behaves identically whether built by the caller or by
`add_middleware` itself.

Backward compatible: `add_middleware(Cls)` and
`add_middleware(partial(Cls, key=val))` both still work exactly as today.

## Component 2: `enable_*` convenience methods on `Velocix`

**File:** `velocix/core/app.py`

Six thin wrapper methods, each importing its middleware lazily (matching
the existing lazy-import style already used in `_setup_docs_routes`) and
calling the new kwargs-aware `add_middleware`. Modeled directly on the
logic that already exists in `create_app()` (`velocix/__init__.py:94-114`)
for CORS and rate limiting.

```python
def enable_cors(
    self,
    allow_origins: list[str] | None = None,
    allow_methods: list[str] | None = None,
    allow_headers: list[str] | None = None,
    allow_credentials: bool = False,
    max_age: int = 600,
    allow_origin_regex: str | None = None,
) -> None:
    """Add CORS support. Wraps velocix.security.cors.CORSMiddleware."""
    from velocix.security.cors import CORSMiddleware
    self.add_middleware(
        CORSMiddleware,
        allow_origins=allow_origins,
        allow_methods=allow_methods,
        allow_headers=allow_headers,
        allow_credentials=allow_credentials,
        max_age=max_age,
        allow_origin_regex=allow_origin_regex,
    )

def enable_csrf(self, secret_key: str, **kwargs: Any) -> None:
    """Add CSRF double-submit-cookie protection. Wraps
    velocix.security.csrf.CSRFMiddleware. Extra kwargs (cookie_name,
    exempt_paths, etc.) pass through."""
    from velocix.security.csrf import CSRFMiddleware
    self.add_middleware(CSRFMiddleware, secret_key=secret_key, **kwargs)

def enable_sessions(self, secret_key: str, **kwargs: Any) -> None:
    """Add signed cookie sessions. Wraps
    velocix.core.middleware.SessionMiddleware. Extra kwargs (max_age,
    same_site, etc.) pass through."""
    from velocix.core.middleware import SessionMiddleware
    self.add_middleware(SessionMiddleware, secret_key=secret_key, **kwargs)

def enable_rate_limit(self, limit: int = 100, window: float = 60) -> None:
    """Add a global rate limit. Wraps
    velocix.security.ratelimit.RateLimitMiddleware with a
    ProductionRateLimiter configured for a single global sliding window."""
    from velocix.security.ratelimit import ProductionRateLimiter, RateLimitMiddleware
    limiter = ProductionRateLimiter()
    limiter.set_global_window(limit=limit, window_size=window)
    self.add_middleware(RateLimitMiddleware, limiter=limiter)

def enable_gzip(self, minimum_size: int = 500, compresslevel: int = 9) -> None:
    """Add gzip response compression. Wraps
    velocix.core.middleware.GZipMiddleware."""
    from velocix.core.middleware import GZipMiddleware
    self.add_middleware(GZipMiddleware, minimum_size=minimum_size, compresslevel=compresslevel)

def enable_trusted_hosts(self, allowed_hosts: list[str]) -> None:
    """Restrict accepted Host headers. Wraps
    velocix.core.middleware.TrustedHostMiddleware."""
    from velocix.core.middleware import TrustedHostMiddleware
    self.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)
```

Each method's kwargs/defaults mirror the wrapped middleware's own
constructor exactly — no new defaults are invented. `enable_csrf` and
`enable_sessions` take `**kwargs` (rather than spelling out every param)
because both middlewares have several optional settings and the only
consistently-required one is `secret_key`; `enable_cors` spells out params
explicitly since callers commonly need to see the options (origins,
methods, headers) to fill in.

No new `__slots__` entries needed — these methods only call
`self.add_middleware`, they don't add app state.

## Component 3: Top-level export audit

**File:** `velocix/__init__.py`

Add imports + `__all__` entries for names that exist today but aren't
reachable from `velocix` directly:

- `TrustedHostMiddleware`, `GZipMiddleware`, `BaseHTTPMiddleware` (from
  `velocix.core.middleware`)
- `CSRFMiddleware` (from `velocix.security.csrf`)
- `Body` (from `velocix.core.params`, joining the already-exported
  `Query`/`Header`/`Cookie`/`Form`/`File`)
- `Struct` — re-exported directly as `msgspec.Struct` (`from msgspec import
  Struct`), so `from velocix import Struct` works without ever touching
  `velocix.validation` or a separate `msgspec` import. `velocix.validation.Struct`
  keeps working unchanged (it's the same object).

## Component 4: README + example refresh

**Files:** `README.md`, `examples/openapi_example.py`

- README quickstart gains a short "Middleware & security" section showing
  `app.enable_cors(...)` instead of the raw `add_middleware`/`partial`
  pattern.
- `examples/openapi_example.py` currently imports `from velocix.validation
  import Struct` and ends by calling `enable_auto_docs(...)` — redundant
  with the automatic docs `Velocix()` already sets up in `__init__`
  (confirmed in `app.py:942-1099`). Update the example to import `Struct`
  from `velocix` directly and drop the `enable_auto_docs` call entirely, so
  the shipped example demonstrates the already-automatic behavior instead of
  the legacy manual path. (The legacy pipeline itself is untouched per
  Non-goals — this only changes what the example teaches.)

## Testing

One test file, following the existing per-feature convention
(`tests/test_security_*.py`):

**`tests/test_app_sugar.py`**
- `add_middleware(Cls, **kwargs)` registers a middleware that receives
  those kwargs (assert via a middleware that records its init args).
- `add_middleware(Cls)` and `add_middleware(partial(Cls, ...))` still work
  (regression coverage for backward compatibility).
- Each `enable_*` method, via `TestClient`: `enable_cors` produces the
  right `access-control-allow-origin` header; `enable_csrf` blocks an
  unauthenticated POST with 403 and passes a GET; `enable_sessions` round-trips
  a session value; `enable_rate_limit` returns 429 after the configured
  limit; `enable_gzip` compresses a large response; `enable_trusted_hosts`
  rejects an unlisted Host header.
- Top-level imports resolve: `from velocix import (TrustedHostMiddleware,
  GZipMiddleware, BaseHTTPMiddleware, CSRFMiddleware, Body, Struct)` and
  `Struct is msgspec.Struct`.

## Compatibility

Purely additive — every existing import, class, and method signature keeps
working unchanged. No app using today's API needs to change anything.
