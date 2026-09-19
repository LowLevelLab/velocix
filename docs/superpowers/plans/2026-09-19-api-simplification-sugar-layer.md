# API Simplification: Additive Sugar Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make common Velocix setup (middleware config, security features, imports) shorter and more discoverable without changing or removing anything that exists today.

**Architecture:** Four additive changes to `velocix/core/app.py` and `velocix/__init__.py`: (1) `add_middleware` accepts `*args`/`**kwargs` directly instead of requiring `functools.partial`, (2) six `enable_*` convenience methods on `Velocix` wrap the existing middleware classes with `add_middleware`, (3) a top-level export audit adds currently-missing names to `velocix/__init__.py`, (4) the README and shipped example are updated to demonstrate the simplified path. No existing class, function, or method signature changes behavior for existing callers.

**Tech Stack:** Python 3.11+, pytest, existing Velocix test conventions (`asyncio.run`-wrapped scenario functions, `TestClient`).

**Spec:** `docs/superpowers/specs/2026-09-19-api-simplification-sugar-layer-design.md`

## Global Constraints

- Purely additive: no existing import, class, method signature, or behavior may change for callers using today's API.
- No new top-level entry point — `Velocix` remains the only app class.
- No changes to the DI/marker system (`Query`, `Header`, `Cookie`, `Body`, `Form`, `File`, `Depends`).
- No deletion, deprecation, or modification of the duplicate `CORSMiddleware`, the redundant OpenAPI/docs pipelines, or the `velocix.validation.Struct` alias — explicitly out of scope.
- Every `enable_*` method's parameters and defaults must match the wrapped middleware's own constructor exactly — no new defaults invented.

**Environment setup:** this repo's dependencies (including `nh3`, used by
`velocix.security.input_sanitization`) are not installed in a bare
`python3`/`pip` on this machine — running `pytest` without setup fails
collection with `ModuleNotFoundError: No module named 'nh3'`. Before Task 1,
create/activate a venv and run `pip install -r requirements.txt -e .` from
the repo root; run all `pytest`/`ruff`/`mypy` commands in this plan inside
that environment.

---

### Task 1: `add_middleware` accepts config directly

**Files:**
- Modify: `velocix/core/app.py` (imports block ~line 1-24, `add_middleware` method ~line 373-375)
- Test: `tests/test_app_sugar.py` (new file)

**Interfaces:**
- Produces: `Velocix.add_middleware(middleware_class, *args, **kwargs)` — when `args` or `kwargs` are given, wraps `middleware_class` in `functools.partial(middleware_class, *args, **kwargs)` before appending to `self._middleware_stack`. Bare-class and pre-built-`partial` calls behave exactly as before.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_app_sugar.py`:

```python
"""Tests for the additive API-simplification sugar layer: add_middleware
kwargs support, enable_* convenience methods, and top-level exports.
"""

import asyncio
from functools import partial

from velocix import TestClient, Velocix
from velocix.core.middleware import BaseMiddleware


def _run(coro):
    return asyncio.run(coro)


class _RecordingMiddleware(BaseMiddleware):
    """Records the kwargs it was constructed with."""

    last_kwargs: dict = {}

    def __init__(self, app, **kwargs):
        super().__init__(app)
        _RecordingMiddleware.last_kwargs = kwargs

    async def __call__(self, request):
        return await self.app(request)


def test_add_middleware_accepts_kwargs_without_partial():
    app = Velocix()

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    app.add_middleware(_RecordingMiddleware, greeting="hi")

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/ping")
            assert resp.status_code == 200

    _run(scenario())
    assert _RecordingMiddleware.last_kwargs == {"greeting": "hi"}


def test_add_middleware_bare_class_still_works():
    app = Velocix()

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    app.add_middleware(_RecordingMiddleware)

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/ping")
            assert resp.status_code == 200

    _run(scenario())
    assert _RecordingMiddleware.last_kwargs == {}


def test_add_middleware_with_partial_still_works():
    app = Velocix()

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    app.add_middleware(partial(_RecordingMiddleware, greeting="via-partial"))

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/ping")
            assert resp.status_code == 200

    _run(scenario())
    assert _RecordingMiddleware.last_kwargs == {"greeting": "via-partial"}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_app_sugar.py -v`
Expected: `test_add_middleware_accepts_kwargs_without_partial` FAILS with
`TypeError: add_middleware() takes 2 positional arguments but 3 were given`
(or similar — the current `add_middleware(self, middleware_class)` doesn't
accept `greeting="hi"`). The other two tests should already PASS (bare
class and `partial` already work today) — that's expected, they're
regression coverage for this task, not new behavior.

- [ ] **Step 3: Implement `add_middleware` kwargs support**

In `velocix/core/app.py`, add the import (insert alphabetically — after
`from collections.abc import ...`, before `from typing import Any`):

```python
from functools import partial
```

Replace the `add_middleware` method:

```python
    def add_middleware(
        self,
        middleware_class: type[BaseMiddleware] | Callable[..., Any],
        *args: Any,
        **kwargs: Any,
    ) -> None:
        """Add middleware to the stack.

        Extra positional/keyword args are bound to the middleware's
        constructor (after `app`), so config no longer requires
        `functools.partial`:

            app.add_middleware(CORSMiddleware, allow_origins=["https://example.com"])

        A bare class or an already-partial'd callable still works unchanged.
        """
        if args or kwargs:
            middleware_class = partial(middleware_class, *args, **kwargs)
        self._middleware_stack.append(middleware_class)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_app_sugar.py -v`
Expected: all 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add velocix/core/app.py tests/test_app_sugar.py
git commit -m "feat(app): add_middleware accepts config directly, no functools.partial needed"
```

---

### Task 2: `enable_*` convenience methods on `Velocix`

**Files:**
- Modify: `velocix/core/app.py` (add methods immediately after `add_middleware`)
- Test: `tests/test_app_sugar.py` (append to file from Task 1)

**Interfaces:**
- Consumes: `Velocix.add_middleware(middleware_class, *args, **kwargs)` from Task 1.
- Produces: `Velocix.enable_cors(...)`, `.enable_csrf(secret_key, **kwargs)`, `.enable_sessions(secret_key, **kwargs)`, `.enable_rate_limit(limit=100, window=60)`, `.enable_gzip(minimum_size=500, compresslevel=9)`, `.enable_trusted_hosts(allowed_hosts)` — each registers the corresponding middleware via `add_middleware`.

Each method below is its own test-then-implement-then-commit cycle.

#### 2a. `enable_cors`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_app_sugar.py`:

```python
def test_enable_cors_adds_allow_origin_header():
    app = Velocix()
    app.enable_cors(allow_origins=["https://example.com"])

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/ping", headers={"origin": "https://example.com"})
            assert resp.headers["access-control-allow-origin"] == "https://example.com"

    _run(scenario())
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_app_sugar.py::test_enable_cors_adds_allow_origin_header -v`
Expected: FAIL with `AttributeError: 'Velocix' object has no attribute 'enable_cors'`

- [ ] **Step 3: Implement `enable_cors`**

In `velocix/core/app.py`, add immediately after `add_middleware`:

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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_app_sugar.py::test_enable_cors_adds_allow_origin_header -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add velocix/core/app.py tests/test_app_sugar.py
git commit -m "feat(app): add enable_cors convenience method"
```

#### 2b. `enable_csrf`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_app_sugar.py`:

```python
def test_enable_csrf_blocks_post_without_token():
    app = Velocix()
    app.enable_csrf(secret_key="test-secret")

    @app.post("/page")
    async def post_page():
        return {"ok": True}

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.post("/page")
            assert resp.status_code == 403
            assert resp.json()["error"]["code"] == "CSRF_COOKIE_MISSING"

    _run(scenario())
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_app_sugar.py::test_enable_csrf_blocks_post_without_token -v`
Expected: FAIL with `AttributeError: 'Velocix' object has no attribute 'enable_csrf'`

- [ ] **Step 3: Implement `enable_csrf`**

Add immediately after `enable_cors`:

```python
    def enable_csrf(self, secret_key: str, **kwargs: Any) -> None:
        """Add CSRF double-submit-cookie protection. Wraps
        velocix.security.csrf.CSRFMiddleware. Extra kwargs (cookie_name,
        exempt_paths, etc.) pass through."""
        from velocix.security.csrf import CSRFMiddleware

        self.add_middleware(CSRFMiddleware, secret_key=secret_key, **kwargs)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_app_sugar.py::test_enable_csrf_blocks_post_without_token -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add velocix/core/app.py tests/test_app_sugar.py
git commit -m "feat(app): add enable_csrf convenience method"
```

#### 2c. `enable_sessions`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_app_sugar.py`:

```python
def test_enable_sessions_round_trips_value():
    app = Velocix()
    app.enable_sessions(secret_key="test-secret")

    @app.get("/set")
    async def set_session(request):
        request.session["user"] = "alice"
        return {"ok": True}

    @app.get("/read")
    async def read_session(request):
        return dict(request.session)

    async def scenario():
        async with TestClient(app) as client:
            await client.get("/set")
            resp = await client.get("/read")
            assert resp.json() == {"user": "alice"}

    _run(scenario())
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_app_sugar.py::test_enable_sessions_round_trips_value -v`
Expected: FAIL with `AttributeError: 'Velocix' object has no attribute 'enable_sessions'`

- [ ] **Step 3: Implement `enable_sessions`**

Add immediately after `enable_csrf`:

```python
    def enable_sessions(self, secret_key: str, **kwargs: Any) -> None:
        """Add signed cookie sessions. Wraps
        velocix.core.middleware.SessionMiddleware. Extra kwargs (max_age,
        same_site, etc.) pass through."""
        from velocix.core.middleware import SessionMiddleware

        self.add_middleware(SessionMiddleware, secret_key=secret_key, **kwargs)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_app_sugar.py::test_enable_sessions_round_trips_value -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add velocix/core/app.py tests/test_app_sugar.py
git commit -m "feat(app): add enable_sessions convenience method"
```

#### 2d. `enable_rate_limit`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_app_sugar.py`:

```python
def test_enable_rate_limit_returns_429_after_limit():
    app = Velocix()
    app.enable_rate_limit(limit=2, window=60)

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    async def scenario():
        async with TestClient(app) as client:
            assert (await client.get("/ping")).status_code == 200
            assert (await client.get("/ping")).status_code == 200
            resp = await client.get("/ping")
            assert resp.status_code == 429

    _run(scenario())
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_app_sugar.py::test_enable_rate_limit_returns_429_after_limit -v`
Expected: FAIL with `AttributeError: 'Velocix' object has no attribute 'enable_rate_limit'`

- [ ] **Step 3: Implement `enable_rate_limit`**

Add immediately after `enable_sessions`:

```python
    def enable_rate_limit(self, limit: int = 100, window: float = 60) -> None:
        """Add a global rate limit. Wraps
        velocix.security.ratelimit.RateLimitMiddleware with a
        ProductionRateLimiter configured for a single global sliding
        window."""
        from velocix.security.ratelimit import ProductionRateLimiter, RateLimitMiddleware

        limiter = ProductionRateLimiter()
        limiter.set_global_window(limit=limit, window_size=window)
        self.add_middleware(RateLimitMiddleware, limiter=limiter)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_app_sugar.py::test_enable_rate_limit_returns_429_after_limit -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add velocix/core/app.py tests/test_app_sugar.py
git commit -m "feat(app): add enable_rate_limit convenience method"
```

#### 2e. `enable_gzip`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_app_sugar.py`:

```python
def test_enable_gzip_compresses_large_response():
    app = Velocix()
    app.enable_gzip(minimum_size=10)

    @app.get("/big")
    async def big():
        return {"data": "x" * 1000}

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/big", headers={"accept-encoding": "gzip"})
            assert resp.headers.get("content-encoding") == "gzip"

    _run(scenario())
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_app_sugar.py::test_enable_gzip_compresses_large_response -v`
Expected: FAIL with `AttributeError: 'Velocix' object has no attribute 'enable_gzip'`

- [ ] **Step 3: Implement `enable_gzip`**

Add immediately after `enable_rate_limit`:

```python
    def enable_gzip(self, minimum_size: int = 500, compresslevel: int = 9) -> None:
        """Add gzip response compression. Wraps
        velocix.core.middleware.GZipMiddleware."""
        from velocix.core.middleware import GZipMiddleware

        self.add_middleware(
            GZipMiddleware, minimum_size=minimum_size, compresslevel=compresslevel
        )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_app_sugar.py::test_enable_gzip_compresses_large_response -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add velocix/core/app.py tests/test_app_sugar.py
git commit -m "feat(app): add enable_gzip convenience method"
```

#### 2f. `enable_trusted_hosts`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_app_sugar.py`:

```python
def test_enable_trusted_hosts_rejects_unlisted_host():
    app = Velocix()
    app.enable_trusted_hosts(["example.com"])

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/ping", headers={"host": "evil.com"})
            assert resp.status_code == 400

    _run(scenario())
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_app_sugar.py::test_enable_trusted_hosts_rejects_unlisted_host -v`
Expected: FAIL with `AttributeError: 'Velocix' object has no attribute 'enable_trusted_hosts'`

- [ ] **Step 3: Implement `enable_trusted_hosts`**

Add immediately after `enable_gzip`:

```python
    def enable_trusted_hosts(self, allowed_hosts: list[str]) -> None:
        """Restrict accepted Host headers. Wraps
        velocix.core.middleware.TrustedHostMiddleware."""
        from velocix.core.middleware import TrustedHostMiddleware

        self.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_app_sugar.py::test_enable_trusted_hosts_rejects_unlisted_host -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add velocix/core/app.py tests/test_app_sugar.py
git commit -m "feat(app): add enable_trusted_hosts convenience method"
```

---

### Task 3: Top-level export audit

**Files:**
- Modify: `velocix/__init__.py`
- Test: `tests/test_app_sugar.py` (append)

**Interfaces:**
- Produces: `velocix.TrustedHostMiddleware`, `velocix.GZipMiddleware`, `velocix.BaseHTTPMiddleware`, `velocix.CSRFMiddleware`, `velocix.Body`, `velocix.Struct` (== `msgspec.Struct`) all importable from the top-level `velocix` package.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_app_sugar.py`:

```python
def test_top_level_exports_resolve():
    import msgspec

    from velocix import (
        BaseHTTPMiddleware,
        Body,
        CSRFMiddleware,
        GZipMiddleware,
        Struct,
        TrustedHostMiddleware,
    )

    assert Struct is msgspec.Struct
    assert Body is not None
    assert TrustedHostMiddleware is not None
    assert GZipMiddleware is not None
    assert BaseHTTPMiddleware is not None
    assert CSRFMiddleware is not None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_app_sugar.py::test_top_level_exports_resolve -v`
Expected: FAIL with `ImportError: cannot import name 'BaseHTTPMiddleware' from 'velocix'`

- [ ] **Step 3: Add the exports**

In `velocix/__init__.py`:

Change the middleware import line:

```python
from velocix.core.middleware import BaseMiddleware, SessionMiddleware
```

to:

```python
from velocix.core.middleware import (
    BaseHTTPMiddleware,
    BaseMiddleware,
    GZipMiddleware,
    SessionMiddleware,
    TrustedHostMiddleware,
)
```

Change the params import line:

```python
from velocix.core.params import Cookie, File, Form, Header, Query
```

to:

```python
from velocix.core.params import Body, Cookie, File, Form, Header, Query
```

Add a new import for `Struct` (as a direct `msgspec.Struct` re-export) and
`CSRFMiddleware`, near the existing `from velocix.security.cors import
CORSMiddleware` line:

```python
from velocix.security.cors import CORSMiddleware
from velocix.security.csrf import CSRFMiddleware
```

And near the top, alongside other stdlib-adjacent imports:

```python
from msgspec import Struct
```

Finally, add all six new names to `__all__` (insert into the existing list,
keeping the grouped-by-section style already there):

```python
    "BaseHTTPMiddleware",
    "TrustedHostMiddleware",
    "GZipMiddleware",
    "CSRFMiddleware",
    "Body",
    "Struct",
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_app_sugar.py::test_top_level_exports_resolve -v`
Expected: PASS

- [ ] **Step 5: Run the full test suite to confirm no regressions**

Run: `pytest -q`
Expected: zero failures — the full existing suite plus the 10 new tests
added across Tasks 1-3 (3 in Task 1, 6 in Task 2, 1 in Task 3), all passing.

- [ ] **Step 6: Commit**

```bash
git add velocix/__init__.py tests/test_app_sugar.py
git commit -m "feat: export BaseHTTPMiddleware, TrustedHostMiddleware, GZipMiddleware, CSRFMiddleware, Body, Struct from top-level velocix"
```

---

### Task 4: README + example refresh

**Files:**
- Modify: `README.md`
- Modify: `examples/openapi_example.py`

**Interfaces:**
- Consumes: `Velocix.enable_cors` (Task 2a), top-level `Struct` (Task 3).
- No new interfaces produced — documentation/example only.

- [ ] **Step 1: Update the README quickstart**

In `README.md`, after the existing Quick Start code block (currently ending
around line 111 with the `uvicorn.run(app, ...)` block), add a new
subsection:

```markdown
### Middleware & security

Common setups are one call — no need to import `functools.partial` or know
the underlying middleware class names:

\`\`\`python
app.enable_cors(allow_origins=["https://example.com"])
app.enable_csrf(secret_key="your-secret")
app.enable_sessions(secret_key="your-secret")
app.enable_rate_limit(limit=100, window=60)
app.enable_gzip()
app.enable_trusted_hosts(["example.com"])
\`\`\`

For anything these don't cover, `app.add_middleware(MiddlewareClass,
**kwargs)` works directly — no `functools.partial` needed there either.
```

(Use literal triple-backtick fences, not escaped, when editing the file —
the `\`\`\`` above is just to avoid closing this plan's own code block
early.)

- [ ] **Step 2: Update the OpenAPI example's import**

In `examples/openapi_example.py`, change:

```python
from velocix.validation import Struct
```

to:

```python
from velocix import Struct
```

- [ ] **Step 3: Remove the redundant `enable_auto_docs` call**

In `examples/openapi_example.py`, delete the entire block starting at
`# Enable automatic OpenAPI documentation` through the closing `)` of the
`enable_auto_docs(...)` call (the block immediately before the
`if __name__ == "__main__":` section). `Velocix()` already registers
`/docs`, `/redoc`, and `/openapi.json` automatically at app creation
(`velocix/core/app.py::_setup_docs_routes`), so this call was generating
those same routes a second time via the separate legacy pipeline.

Also remove the now-unused import at the top of the file:

```python
from velocix.openapi import enable_auto_docs
```

- [ ] **Step 4: Verify the example still parses and runs**

Run: `python -c "import ast; ast.parse(open('examples/openapi_example.py').read())"`
Expected: no output (valid syntax).

Run: `python -c "import examples.openapi_example as m; print(m.app.docs_url, m.app.openapi_url)"`
Expected: prints `/docs /openapi.json` — confirms the app still has working
docs routes via the automatic mechanism, without the removed manual call.

- [ ] **Step 5: Run the full test suite, ruff, and mypy**

Run: `pytest -q && ruff check . && mypy velocix`
Expected: zero test failures, zero ruff violations, zero mypy errors —
matching the standard the repo already holds itself to (see commit 6ac2f55,
which reported "262/262 tests, mypy clean, ruff clean" for its own change).

- [ ] **Step 6: Commit**

```bash
git add README.md examples/openapi_example.py
git commit -m "docs: demonstrate enable_* helpers in README and drop redundant enable_auto_docs from example"
```

---

## Self-Review Notes

- **Spec coverage:** Component 1 → Task 1. Component 2 (all six methods) →
  Task 2a-2f. Component 3 → Task 3. Component 4 → Task 4. Testing section →
  covered across all tasks in `tests/test_app_sugar.py`. Compatibility
  section → enforced by Global Constraints and the regression tests in
  Task 1 (bare class / `partial` still work).
- **Placeholder scan:** none found — every step has runnable code.
- **Type consistency:** `add_middleware(middleware_class, *args, **kwargs)`
  signature from Task 1 is reused identically by every `enable_*` method in
  Task 2. `Struct` in Task 3 is the same object referenced in Task 4 Step 2.
