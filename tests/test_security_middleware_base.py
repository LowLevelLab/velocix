"""Regression test for issue #17: SecurityMiddleware.__call__ used to catch
ANY exception from _on_request. Since PR #16, self.app(request) itself
essentially never raises anymore -- the compiled middleware terminal
already converts routing failures and handler-raised HTTPExceptions into
real Responses before they get back here. So the exception this catch
block actually swallowed was from a middleware's own code that runs AFTER
a successful self.app(request) call (e.g. CSRFMiddleware setting a cookie
on the response it got back). Catching that and calling self.app(request)
again meant the downstream handler -- and any side effect it has -- ran a
second time for one incoming request.
"""

import asyncio

from velocix import TestClient, Velocix
from velocix.security.base import SecurityMiddleware


class _BuggyPostProcessSecurity(SecurityMiddleware):
    """Calls through to self.app like every real subclass, then does its
    own post-processing on the response -- which has a bug."""

    async def _on_request(self, request):
        _response = await self.app(request)
        raise RuntimeError("bug in this middleware's own post-processing")


def _run(coro):
    return asyncio.run(coro)


def test_downstream_handler_not_invoked_twice_on_post_processing_bug():
    call_count = 0

    app = Velocix()

    @app.get("/side-effect")
    async def side_effect():
        nonlocal call_count
        call_count += 1
        return {"ok": True}

    app.add_middleware(_BuggyPostProcessSecurity)

    async def scenario():
        async with TestClient(app) as client:
            resp = await client.get("/side-effect")
            assert resp.status_code == 500

    _run(scenario())

    assert call_count == 1
