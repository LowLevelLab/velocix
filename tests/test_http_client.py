"""HTTPClient had zero test coverage before this: connect() hardcoded
http2=True in the httpx.AsyncClient(...) call, which raises ImportError
unless the optional 'h2' package is installed -- never declared as a
dependency anywhere, so the default constructor was unusable out of the
box for anyone who only installed velocix's declared requirements.
"""

import asyncio

from velocix.http.client import HTTPClient


def _run(coro):
    return asyncio.run(coro)


def test_default_client_connects_without_h2_installed():
    async def scenario():
        client = HTTPClient()
        await client.connect()
        assert not client.is_closed
        await client.close()

    _run(scenario())


def test_default_client_as_context_manager():
    async def scenario():
        async with HTTPClient() as client:
            assert not client.is_closed

    _run(scenario())


def test_http2_is_opt_in():
    async def scenario():
        client = HTTPClient(http2=False)
        await client.connect()
        await client.close()

    _run(scenario())
