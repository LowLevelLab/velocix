import asyncio
from typing import Annotated

from velocix import Query, TestClient, Velocix
from velocix.core.depends import Depends
from velocix.core.exceptions import HTTPException


def _run(coro):
    return asyncio.run(coro)


def test_simple_depends():
    async def get_config(request):
        return {"debug": True}

    app = Velocix()

    @app.get("/config")
    async def config_endpoint(config: dict = Depends(get_config)):
        return config

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/config")
            assert resp.json() == {"debug": True}

    _run(scenario())


def test_async_depends():
    async def get_data(request):
        await asyncio.sleep(0)
        return {"key": "value"}

    app = Velocix()

    @app.get("/data")
    async def get_data_endpoint(data: dict = Depends(get_data)):
        return data

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/data")
            assert resp.json() == {"key": "value"}

    _run(scenario())


def test_sync_depends():
    events = []

    def get_config(request):
        events.append("called")
        return {"debug": True}

    app = Velocix()

    @app.get("/config")
    async def config_endpoint(config: dict = Depends(get_config)):
        return config

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/config")
            assert resp.json() == {"debug": True}
            assert events == ["called"]

    _run(scenario())


def test_depends_raises_http_exception():
    async def require_auth(request):
        raise HTTPException(status_code=401, detail="Not authenticated")

    app = Velocix()

    @app.get("/secure")
    async def secure(data: str = Depends(require_auth)):
        return {"data": data}

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/secure")
            assert resp.status_code == 401

    _run(scenario())


def test_depends_with_path_params_in_handler():
    async def get_user(request):
        return "alice"

    app = Velocix()

    @app.get("/users/{user_id}")
    async def get_user_endpoint(user_id: int, user: str = Depends(get_user)):
        return {"user_id": user_id, "user": user}

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/users/42")
            assert resp.json() == {"user_id": 42, "user": "alice"}

    _run(scenario())


def test_multiple_depends_same_handler():
    async def dep_a(request):
        return "a"

    async def dep_b(request):
        return "b"

    app = Velocix()

    @app.get("/multi")
    async def multi(a: str = Depends(dep_a), b: str = Depends(dep_b)):
        return {"a": a, "b": b}

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/multi")
            assert resp.json() == {"a": "a", "b": "b"}

    _run(scenario())


def test_depends_use_cache_false():
    call_count = 0

    async def uncached(request):
        nonlocal call_count
        call_count += 1
        return "fresh"

    app = Velocix()

    @app.get("/uncached-dep")
    async def endpoint(data: str = Depends(uncached, use_cache=False)):
        return {"data": data}

    async def scenario():
        async with TestClient(app) as client:
            await client.get("/uncached-dep")
            await client.get("/uncached-dep")
            assert call_count == 2

    _run(scenario())


def test_depends_with_query():
    async def get_version(request):
        return "v1"

    app = Velocix()

    @app.get("/items")
    async def items(q: Annotated[str, Query()] = "all", version: str = Depends(get_version)):
        return {"q": q, "version": version}

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/items?q=search")
            assert resp.json() == {"q": "search", "version": "v1"}

    _run(scenario())


def test_depends_exception_returns_500():
    async def broken(request):
        raise RuntimeError("database down")

    app = Velocix()

    @app.get("/broken")
    async def broken_endpoint(data: str = Depends(broken)):
        return {"data": data}

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/broken")
            assert resp.status_code == 500

    _run(scenario())


def test_depends_with_body():
    import msgspec

    class Item(msgspec.Struct):
        name: str

    async def get_user(request):
        return "alice"

    app = Velocix()

    @app.post("/orders")
    async def create(item: Item, user: str = Depends(get_user)):
        return {"name": item.name, "user": user}

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.post("/orders", json={"name": "widget"})
            assert resp.json() == {"name": "widget", "user": "alice"}

    _run(scenario())


def test_depends_request_has_app():
    app = Velocix()

    async def check_app(request):
        return request.app is app

    @app.get("/check")
    async def check(is_app: bool = Depends(check_app)):
        return {"is_app": is_app}

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/check")
            assert resp.json() == {"is_app": True}

    _run(scenario())


def test_depends_request_has_method():
    app = Velocix()

    async def get_method(request):
        return request.method

    @app.get("/method")
    async def method(m: str = Depends(get_method)):
        return {"method": m}

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/method")
            assert resp.json() == {"method": "GET"}

    _run(scenario())


def test_depends_with_path_and_query():
    async def get_context(request):
        return {"method": request.method}

    app = Velocix()

    @app.get("/items/{item_id}")
    async def get_item(
        item_id: int,
        ctx: dict = Depends(get_context),
        verbose: Annotated[bool, Query()] = False,
    ):
        return {"item_id": item_id, "method": ctx["method"], "verbose": verbose}

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/items/7?verbose=true")
            assert resp.json() == {"item_id": 7, "method": "GET", "verbose": True}

    _run(scenario())
