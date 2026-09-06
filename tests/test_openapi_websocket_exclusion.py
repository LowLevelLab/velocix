"""Regression test: WebSocket routes used to show up in /openapi.json as an
empty, spec-invalid Path Item Object ({}) -- PathItem has no "websocket"
field, so setattr(path_item, "websocket", op) silently created a dangling
attribute to_dict() never serialized, and the path stayed in the schema
with no operations at all.
"""

import asyncio

from velocix import TestClient, Velocix
from velocix.websocket.connection import WebSocket


def _run(coro):
    return asyncio.run(coro)


def test_websocket_route_excluded_from_openapi_schema():
    app = Velocix()

    @app.get("/posts")
    async def list_posts():
        return {"posts": []}

    @app.websocket("/ws/posts/{post_id}")
    async def watch_post(websocket: WebSocket):
        await websocket.accept()
        await websocket.close()

    async def scenario():
        async with TestClient(app) as client:
            schema = (await client.get("/openapi.json")).json()
            paths = schema.get("paths", {})
            assert "/posts" in paths
            assert "get" in paths["/posts"]
            assert "/ws/posts/{post_id}" not in paths

    _run(scenario())
