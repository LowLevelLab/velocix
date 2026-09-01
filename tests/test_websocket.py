import asyncio

from velocix import Velocix
from velocix.testing.client import TestClient
from velocix.websocket.connection import WebSocket, WebSocketManager


def _run(coro):
    return asyncio.run(coro)


def test_websocket_text_echo():
    app = Velocix()

    @app.websocket("/ws")
    async def ws_endpoint(websocket: WebSocket):
        await websocket.accept()
        data = await websocket.receive_text()
        await websocket.send_text(f"echo: {data}")
        await websocket.close()

    async def scenario():
        async with TestClient(app) as client:
            ws = await client.websocket_connect("/ws")
            await asyncio.sleep(0.05)
            await ws.send_text("hello")
            await asyncio.sleep(0.05)
            resp = await ws.receive_text()
            assert resp == "echo: hello"

    _run(scenario())


def test_websocket_binary_echo():
    app = Velocix()

    @app.websocket("/ws")
    async def ws_endpoint(websocket: WebSocket):
        await websocket.accept()
        data = await websocket.receive_bytes()
        await websocket.send_bytes(data)
        await websocket.close()

    async def scenario():
        async with TestClient(app) as client:
            ws = await client.websocket_connect("/ws")
            await asyncio.sleep(0.05)
            await ws.send_bytes(b"\x00\x01\x02")
            await asyncio.sleep(0.05)
            resp = await ws.receive_bytes()
            assert resp == b"\x00\x01\x02"

    _run(scenario())


def test_websocket_json_echo():
    app = Velocix()

    @app.websocket("/ws")
    async def ws_endpoint(websocket: WebSocket):
        await websocket.accept()
        data = await websocket.receive_json()
        await websocket.send_json({"echo": data})
        await websocket.close()

    async def scenario():
        async with TestClient(app) as client:
            ws = await client.websocket_connect("/ws")
            await asyncio.sleep(0.05)
            await ws.send_json({"msg": "hello"})
            await asyncio.sleep(0.05)
            resp = await ws.receive_json()
            assert resp == {"echo": {"msg": "hello"}}

    _run(scenario())


def test_websocket_multiple_messages():
    app = Velocix()

    @app.websocket("/ws")
    async def ws_endpoint(websocket: WebSocket):
        await websocket.accept()
        for _ in range(3):
            data = await websocket.receive_text()
            await websocket.send_text(f"msg:{data}")
        await websocket.close()

    async def scenario():
        async with TestClient(app) as client:
            ws = await client.websocket_connect("/ws")
            await asyncio.sleep(0.05)
            for i in range(3):
                await ws.send_text(f"test{i}")
                await asyncio.sleep(0.05)
                resp = await ws.receive_text()
                assert resp == f"msg:test{i}"

    _run(scenario())


def test_websocket_close_by_handler():
    app = Velocix()

    @app.websocket("/ws")
    async def ws_endpoint(websocket: WebSocket):
        await websocket.accept()
        await websocket.send_text("bye")
        await websocket.close(code=1000, reason="done")

    async def scenario():
        async with TestClient(app) as client:
            ws = await client.websocket_connect("/ws")
            await asyncio.sleep(0.05)
            resp = await ws.receive_text()
            assert resp == "bye"

    _run(scenario())


def test_websocket_iter_text():
    app = Velocix()

    @app.websocket("/ws")
    async def ws_endpoint(websocket: WebSocket):
        await websocket.accept()
        messages = []
        async for msg in websocket.iter_text():
            messages.append(msg)
            if msg == "stop":
                break
        await websocket.send_text(f"got:{len(messages)}")
        await websocket.close()

    async def scenario():
        async with TestClient(app) as client:
            ws = await client.websocket_connect("/ws")
            await asyncio.sleep(0.05)
            await ws.send_text("a")
            await asyncio.sleep(0.05)
            await ws.send_text("b")
            await asyncio.sleep(0.05)
            await ws.send_text("stop")
            await asyncio.sleep(0.05)
            resp = await ws.receive_text()
            assert resp == "got:3"

    _run(scenario())


def test_websocket_path_params():
    app = Velocix()

    @app.websocket("/ws/{room_id}")
    async def ws_endpoint(websocket: WebSocket):
        await websocket.accept()
        room_id = websocket.path_params.get("room_id", "?")
        await websocket.send_text(f"room:{room_id}")
        await websocket.close()

    async def scenario():
        async with TestClient(app) as client:
            ws = await client.websocket_connect("/ws/general")
            await asyncio.sleep(0.05)
            resp = await ws.receive_text()
            assert resp == "room:general"

    _run(scenario())


def test_websocket_accept_idempotent():
    app = Velocix()

    @app.websocket("/ws")
    async def ws_endpoint(websocket: WebSocket):
        await websocket.accept()
        await websocket.accept()  # should be no-op
        await websocket.send_text("ok")
        await websocket.close()

    async def scenario():
        async with TestClient(app) as client:
            ws = await client.websocket_connect("/ws")
            await asyncio.sleep(0.05)
            resp = await ws.receive_text()
            assert resp == "ok"

    _run(scenario())


def test_websocket_nonexistent_path_closes():
    app = Velocix()

    @app.websocket("/ws")
    async def ws_endpoint(websocket: WebSocket):
        await websocket.accept()
        await websocket.send_text("hi")
        await websocket.close()

    async def scenario():
        async with TestClient(app) as client:
            ws = await client.websocket_connect("/nonexistent")
            # no handler -> immediate close, no accept
            resp = await ws.receive()
            assert resp["type"] == "websocket.close"
            assert resp["code"] == 1000

    _run(scenario())


def test_websocket_handler_exception_closes_with_1011():
    app = Velocix()

    @app.websocket("/ws")
    async def ws_endpoint(websocket: WebSocket):
        await websocket.accept()
        raise RuntimeError("handler crashed")

    async def scenario():
        async with TestClient(app) as client:
            ws = await client.websocket_connect("/ws")
            # skip accept, read until close
            resp = await ws.receive()
            if resp["type"] == "websocket.accept":
                resp = await ws.receive()
            assert resp["type"] == "websocket.close"
            assert resp["code"] == 1011

    _run(scenario())


def test_websocket_close_is_idempotent():
    app = Velocix()

    @app.websocket("/ws")
    async def ws_endpoint(websocket: WebSocket):
        await websocket.accept()
        await websocket.close()
        await websocket.close()  # should not raise

    async def scenario():
        async with TestClient(app) as client:
            await client.websocket_connect("/ws")
            await asyncio.sleep(0.05)

    _run(scenario())


def test_websocket_query_string():
    app = Velocix()

    @app.websocket("/ws")
    async def ws_endpoint(websocket: WebSocket):
        await websocket.accept()
        qs = websocket.query_string.decode()
        await websocket.send_text(qs)
        await websocket.close()

    async def scenario():
        async with TestClient(app) as client:
            ws = await client.websocket_connect("/ws", params={"token": "abc"})
            await asyncio.sleep(0.05)
            resp = await ws.receive_text()
            assert "token=abc" in resp

    _run(scenario())


def test_websocket_subprotocol():
    app = Velocix()

    @app.websocket("/ws")
    async def ws_endpoint(websocket: WebSocket):
        await websocket.accept(subprotocol="graphql-ws")
        await websocket.send_text("accepted")
        await websocket.close()

    async def scenario():
        async with TestClient(app) as client:
            ws = await client.websocket_connect("/ws")
            await asyncio.sleep(0.05)
            resp = await ws.receive_text()
            assert resp == "accepted"

    _run(scenario())


def test_websocket_client_id():
    app = Velocix()

    @app.websocket("/ws")
    async def ws_endpoint(websocket: WebSocket):
        await websocket.accept()
        await websocket.send_text(websocket.client_id)
        await websocket.close()

    async def scenario():
        async with TestClient(app) as client:
            ws = await client.websocket_connect("/ws")
            await asyncio.sleep(0.05)
            resp = await ws.receive_text()
            assert "testclient" in resp or "unknown" in resp

    _run(scenario())


def test_websocket_url_property():
    app = Velocix()

    @app.websocket("/ws")
    async def ws_endpoint(websocket: WebSocket):
        await websocket.accept()
        await websocket.send_text(websocket.url)
        await websocket.close()

    async def scenario():
        async with TestClient(app) as client:
            ws = await client.websocket_connect("/ws")
            await asyncio.sleep(0.05)
            resp = await ws.receive_text()
            assert "ws://" in resp
            assert "/ws" in resp

    _run(scenario())


def test_websocket_path_params_from_scope():
    app = Velocix()

    @app.websocket("/ws/{item_id}")
    async def ws_endpoint(websocket: WebSocket):
        await websocket.accept()
        item_id = websocket.path_params.get("item_id", "?")
        await websocket.send_text(f"id:{item_id}")
        await websocket.close()

    async def scenario():
        async with TestClient(app) as client:
            ws = await client.websocket_connect("/ws/42")
            await asyncio.sleep(0.05)
            resp = await ws.receive_text()
            assert resp == "id:42"

    _run(scenario())


def test_websocket_manager_connection_count():
    manager = WebSocketManager()
    assert manager.get_connection_count() == 0


def test_websocket_iter_bytes():
    app = Velocix()

    @app.websocket("/ws")
    async def ws_endpoint(websocket: WebSocket):
        await websocket.accept()
        chunks = []
        async for chunk in websocket.iter_bytes():
            chunks.append(chunk)
            if chunk == b"stop":
                break
        await websocket.send_text(f"count:{len(chunks)}")
        await websocket.close()

    async def scenario():
        async with TestClient(app) as client:
            ws = await client.websocket_connect("/ws")
            await asyncio.sleep(0.05)
            await ws.send_bytes(b"hello")
            await asyncio.sleep(0.05)
            await ws.send_bytes(b"stop")
            await asyncio.sleep(0.05)
            resp = await ws.receive_text()
            assert resp == "count:2"

    _run(scenario())
