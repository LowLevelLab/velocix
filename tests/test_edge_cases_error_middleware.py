import asyncio
from functools import partial

from velocix import CORSMiddleware, TestClient, Velocix
from velocix.core.exceptions import HTTPException
from velocix.core.middleware import BaseHTTPMiddleware
from velocix.core.response import JSONResponse, Response


def _run(coro):
    return asyncio.run(coro)


def test_404_on_unknown_route():
    app = Velocix()

    @app.get("/known")
    async def known():
        return {}

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/unknown")
            assert resp.status_code == 404

    _run(scenario())


def test_405_wrong_method():
    app = Velocix()

    @app.get("/only-get")
    async def only_get():
        return {}

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.post("/only-get")
            assert resp.status_code == 405

    _run(scenario())


def test_http_exception_preserves_status_code():
    app = Velocix()

    @app.get("/forbidden")
    async def forbidden():
        raise HTTPException(status_code=403, detail="No access")

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/forbidden")
            assert resp.status_code == 403
            body = resp.json()
            assert body["error"]["status_code"] == 403

    _run(scenario())


def test_http_exception_with_headers():
    app = Velocix()

    @app.get("/auth")
    async def auth():
        raise HTTPException(
            status_code=401,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Bearer"},
        )

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/auth")
            assert resp.status_code == 401

    _run(scenario())


def test_custom_exception_handler():
    app = Velocix()

    class CustomError(Exception):
        pass

    async def handle_custom(request, exc):
        return JSONResponse({"custom": str(exc)}, status_code=418)

    app.add_exception_handler(CustomError, handle_custom)

    @app.get("/fail")
    async def fail():
        raise CustomError("teapot")

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/fail")
            assert resp.status_code == 418
            assert resp.json() == {"custom": "teapot"}

    _run(scenario())


def test_exception_handler_returns_response():
    app = Velocix()

    class BizError(Exception):
        pass

    async def handle_biz(request, exc):
        return Response("handled", status_code=200)

    app.add_exception_handler(BizError, handle_biz)

    @app.get("/biz")
    async def biz():
        raise BizError("oops")

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/biz")
            assert resp.status_code == 200
            assert resp.text() == "handled"

    _run(scenario())


def test_unhandled_exception_returns_500():
    app = Velocix()

    @app.get("/crash")
    async def crash():
        raise RuntimeError("kaboom")

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/crash")
            assert resp.status_code == 500

    _run(scenario())


def test_exception_handler_wrong_return_type():
    app = Velocix()

    class MyError(Exception):
        pass

    async def bad_handler(request, exc):
        return {"not": "a response"}

    app.add_exception_handler(MyError, bad_handler)

    @app.get("/bad")
    async def bad():
        raise MyError("fail")

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/bad")
            assert resp.status_code == 500

    _run(scenario())


def test_multiple_exception_handlers():
    app = Velocix()

    class ErrorA(Exception):
        pass

    class ErrorB(Exception):
        pass

    async def handle_a(request, exc):
        return JSONResponse({"type": "a"}, status_code=400)

    async def handle_b(request, exc):
        return JSONResponse({"type": "b"}, status_code=422)

    app.add_exception_handler(ErrorA, handle_a)
    app.add_exception_handler(ErrorB, handle_b)

    @app.get("/a")
    async def fail_a():
        raise ErrorA("x")

    @app.get("/b")
    async def fail_b():
        raise ErrorB("y")

    async def scenario():
        async with TestClient(app) as client:
            r1 = await client.get("/a")
            assert r1.status_code == 400
            assert r1.json()["type"] == "a"
            r2 = await client.get("/b")
            assert r2.status_code == 422
            assert r2.json()["type"] == "b"

    _run(scenario())


class BrokenMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        raise RuntimeError("middleware boom")


def test_middleware_exception_returns_500():
    app = Velocix()
    app.add_middleware(BrokenMiddleware)

    @app.get("/ok")
    async def ok():
        return {"ok": True}

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/ok")
            assert resp.status_code == 500

    _run(scenario())


class ShortCircuitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        return Response("blocked", status_code=403)


def test_middleware_returns_response_directly():
    app = Velocix()
    app.add_middleware(ShortCircuitMiddleware)

    @app.get("/ok")
    async def ok():
        return {"ok": True}

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/ok")
            assert resp.status_code == 403
            assert resp.text() == "blocked"

    _run(scenario())


def test_multiple_middleware_execution_order():
    app = Velocix()
    order = []

    class M1(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            order.append("m1-before")
            resp = await call_next(request)
            order.append("m1-after")
            return resp

    class M2(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            order.append("m2-before")
            resp = await call_next(request)
            order.append("m2-after")
            return resp

    app.add_middleware(M1)
    app.add_middleware(M2)

    @app.get("/ok")
    async def ok():
        order.append("handler")
        return {"ok": True}

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/ok")
            assert resp.status_code == 200
            assert order == ["m1-before", "m2-before", "handler", "m2-after", "m1-after"]

    _run(scenario())


def test_cors_middleware_blocks_origin():
    app = Velocix()

    @app.get("/ping")
    async def ping():
        return {"pong": True}

    app.add_middleware(partial(CORSMiddleware, allow_origins=["https://allowed.com"]))

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/ping", headers={"Origin": "https://evil.com"})
            assert "access-control-allow-origin" not in resp.headers

    _run(scenario())


def test_cors_middleware_allows_origin():
    app = Velocix()

    @app.get("/ping")
    async def ping():
        return {"pong": True}

    app.add_middleware(partial(CORSMiddleware, allow_origins=["https://allowed.com"]))

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/ping", headers={"Origin": "https://allowed.com"})
            assert resp.headers["access-control-allow-origin"] == "https://allowed.com"

    _run(scenario())
