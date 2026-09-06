# Velocix

A high-performance ASGI web framework for Python with FastAPI-style ergonomics and a
Starlette-inspired core. Routing, parameter injection, validation, middleware, WebSockets,
OpenAPI, security, and testing utilities — built for measurable speed, not claims.

- Python 3.10+
- Runs on any ASGI server (granian, uvicorn, hypercorn)
- Zero runtime dependencies beyond the fast primitives: `orjson`, `msgspec`,
  `fast-query-parsers`, `xxhash`

---

## Features

**Routing**
- Static, dynamic (`/users/{user_id}`), and typed path params with constraint support
- Named routes and reverse routing: `request.url_for("user", user_id=42)`
- `include_router(router, prefix="/api")` and `app.mount("/static", StaticFiles(...))`
- `status_code=` and `response_model=` on route decorators

**Parameter injection**
- `Query`, `Header`, `Cookie`, `Form`, `File` markers — both `Annotated[...]` and classic
  `= Query(...)` styles
- Request-body binding to msgspec Structs with structured 422 errors
- `Depends` dependency injection with per-request caching

**HTTP**
- Response classes: `Response`, `JSONResponse`, `HTMLResponse`, `PlainTextResponse`,
  `StreamingResponse`, `FileResponse`, `EventStreamResponse` (SSE), `JSONLinesResponse`,
  `RedirectResponse`
- Background tasks run after the response is sent
- `@cache_response` with ETag / `If-None-Match` conditional requests and `Cache-Control`

**Middleware and security**
- `BaseMiddleware` + compiled middleware stack; `CORSMiddleware` (incl. `allow_origin_regex`),
  `TrustedHostMiddleware`, `GZipMiddleware`, `SecurityHeadersMiddleware`, `RequestIDMiddleware`,
  `RateLimitMiddleware`
- Signed session middleware (`SessionMiddleware`) with `request.session`
- JWT auth, password hashing, multipart uploads (`UploadFile`, `MultipartForm`)

**Protocols and tooling**
- WebSockets (text / bytes / JSON, both directions)
- OpenAPI 3.1 generation with Swagger and ReDoc
- `HTTPClient` (httpx-based), `TestClient`, health checks, Prometheus metrics
- Lifespan startup/shutdown handlers, custom exception handlers

---

## Installation

> **The package on PyPI is outdated.** `pip install velocix` currently installs
> `0.1.3`, published before a long series of bug fixes (routing, middleware,
> OpenAPI docs, dependency declarations, and more). Until a new version is
> released, install from source:

```bash
git clone https://github.com/LowLevelLab/velocix.git
cd velocix
pip install -e .
```

Requires Python 3.10 or newer and an ASGI server:

```bash
pip install granian   # or: uvicorn, hypercorn
```

---

## Quick Start

```python
from typing import Annotated

from msgspec import Struct

from velocix import Query, TestClient, Velocix
from velocix.core.response import JSONResponse

app = Velocix()


@app.get("/")
async def hello() -> dict:
    return {"message": "Hello World"}


@app.get("/users/{user_id}")
async def get_user(
    user_id: int,
    limit: Annotated[int, Query()] = 10,
) -> dict:
    return {"user_id": user_id, "limit": limit}


class OrderIn(Struct):
    customer: str
    qty: int


@app.post("/orders", status_code=201)
async def create_order(order: OrderIn) -> dict:
    return {"customer": order.customer, "qty": order.qty}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
```

---

## Performance

All numbers are real measurements — see [docs/PERFORMANCE.md](docs/PERFORMANCE.md) for the
full methodology and [benchmarks/](benchmarks/) for the reproducible harness. Velocix serves
**byte-identical responses** to every framework compared, on the same routes, under the same
load, on the same box.

### Framework floor (in-process, no sockets)

The pure framework cost — routing, parsing, dependency resolution, serialization — with the
ASGI server removed. Measured on a 12-vCPU shared box, Python 3.13.

| Route | req/s | per-request |
|---|---|---|
| `GET /users/42?limit=5` (path + query params) | ~163K | ~6.1 µs |
| `GET /items` (7.9 KB JSON body) | ~51K | ~19.7 µs |

### Live over real HTTP (granian, 4 workers)

| Server | `/users` | `/items` |
|---|---|---|
| granian (Rust ASGI), 4 workers | ~121K req/s | ~92K req/s |
| uvicorn (Python ASGI), 4 workers | ~22K req/s | ~21K req/s |

### Cross-framework wrk2 (granian 4 workers, constant-rate, identical routes)

6 frameworks, wrk2 (HdrHistogram), 10 s per run, 200 connections:

| Route / Rate | Velocix | Starlette | FastAPI | Falcon | BlackSheep | Litestar |
|---|---|---|---|---|---|---|
| `/items` 1K p50 | **1.55 ms** | 1.99 ms | 2.45 ms | 2.01 ms | 1.76 ms | 1.68 ms |
| `/items` 5K p50 | **1.14 ms** | 1.39 ms | 17.66 ms | 2.54 ms | 2.62 ms | 1.44 ms |
| `/items` 5K p99 | **2.39 ms** | 3.51 ms | 234.75 ms | 7.95 ms | 9.87 ms | 3.22 ms |
| `/users/42` 1K p50 | 1.63 ms | 2.15 ms | 2.21 ms | **1.51 ms** | 1.54 ms | 1.65 ms |
| `/users/42` 5K p50 | **1.17 ms** | 1.18 ms | 1.31 ms | 2.08 ms | 1.63 ms | 1.60 ms |
| `/orders` 1K p50 | **1.53 ms** | 1.94 ms | 2.21 ms | 1.91 ms | 1.97 ms | 1.70 ms |
| `/slow` 500 p50 | 7.36 ms | 8.30 ms | 8.22 ms | 7.30 ms | **7.08 ms** | 9.44 ms |

Velocix leads or ties on large payloads (`/items`) and validated POST (`/orders`).
BlackSheep and Falcon edge it out on lightweight `/users/42` at low rates.
FastAPI collapses under load on large payloads (p99 = 234 ms at 5K rps).
I/O-bound routes erase all differences.

Full wrk2 tables in [docs/PERFORMANCE.md](docs/PERFORMANCE.md).

---

## Code Structure

```
velocix/
├── core/           # ASGI app, router, request/response, dependencies, middleware
├── http/           # HTTP client, multipart parsing
├── security/       # JWT, password hashing, CORS, rate limiting
├── validation/     # msgspec-based validation
├── websocket/      # WebSocket support
├── openapi/        # OpenAPI 3.1 generation, Swagger / ReDoc
├── monitoring/     # Health checks and metrics
├── testing/        # TestClient
└── config/         # Configuration helpers
```

---

## Documentation

- [API Reference](docs/API_REFERENCE.md)
- [User Guide](docs/GUIDE.md)
- [Performance](docs/PERFORMANCE.md)
- [Security](docs/SECURITY.md)
- [Internals](docs/INTERNALS.md)

---

## License

MIT — see the [LICENSE](LICENSE) file.
