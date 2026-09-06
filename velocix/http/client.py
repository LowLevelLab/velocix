"""
HTTP client with retry logic, connection pooling, and Starlette-inspired patterns.
Provides async context manager support and efficient request handling.
"""

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx

logger = logging.getLogger("velocix.http")


class ClientDisconnect(Exception):
    """Client disconnected during request"""

    pass


class RequestError(Exception):
    """Request failed after retries"""

    pass


class HTTPClient:
    """
    Async HTTP client with Starlette-inspired patterns.

    Features:
    - Connection pooling and keepalive
    - Automatic retry with exponential backoff
    - Request/response streaming
    - Context manager support
    - Timeout handling
    - Custom headers and auth
    """

    __slots__ = (
        "_client",
        "_timeout",
        "_max_retries",
        "_base_url",
        "_headers",
        "_limits",
        "_verify_ssl",
        "_follow_redirects",
        "_http2",
    )

    def __init__(
        self,
        base_url: str = "",
        timeout: float = 30.0,
        max_retries: int = 3,
        headers: dict[str, str] | None = None,
        max_connections: int = 100,
        max_keepalive: int = 20,
        verify_ssl: bool = True,
        follow_redirects: bool = True,
        http2: bool = False,
    ) -> None:
        self._client: httpx.AsyncClient | None = None
        self._timeout = timeout
        self._max_retries = max_retries
        self._base_url = base_url
        self._headers = headers or {}
        self._limits = httpx.Limits(
            max_keepalive_connections=max_keepalive, max_connections=max_connections
        )
        self._verify_ssl = verify_ssl
        self._follow_redirects = follow_redirects
        # Opt-in: httpx raises ImportError from AsyncClient(http2=True) unless
        # the optional 'h2' package is installed, so defaulting this to True
        # made HTTPClient unusable out of the box for anyone who only
        # installed velocix's declared dependencies (just httpx, no h2).
        self._http2 = http2

    async def __aenter__(self) -> "HTTPClient":
        await self.connect()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    async def connect(self) -> None:
        """
        Initialize HTTP client with connection pooling.
        Idempotent - safe to call multiple times.
        """
        if self._client is not None:
            return

        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            timeout=self._timeout,
            headers=self._headers,
            limits=self._limits,
            verify=self._verify_ssl,
            follow_redirects=self._follow_redirects,
            http2=self._http2,
        )

    async def close(self) -> None:
        """
        Close HTTP client and cleanup connections.
        Safe to call even if not connected.
        """
        if self._client:
            await self._client.aclose()
            self._client = None

    @property
    def is_closed(self) -> bool:
        """Check if client is closed"""
        return self._client is None or self._client.is_closed

    async def request(
        self,
        method: str,
        url: str,
        retry: bool = True,
        retry_on_status: set[int] | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        """
        Make HTTP request with automatic retry and exponential backoff.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL (absolute or relative to base_url)
            retry: Enable retry logic
            retry_on_status: Status codes to retry on (default: 5xx errors)
            **kwargs: Additional httpx request parameters

        Returns:
            httpx.Response object

        Raises:
            RequestError: If all retry attempts fail
            ClientDisconnect: If client disconnects during request
        """
        if not self._client:
            await self.connect()
        if self._client is None:
            raise RuntimeError("HTTP client is not connected")

        if not retry:
            try:
                return await self._client.request(method, url, **kwargs)
            except httpx.RemoteProtocolError as exc:
                raise ClientDisconnect(f"Remote disconnected: {exc}") from exc

        retry_status_codes = retry_on_status or {500, 502, 503, 504}
        last_error = None
        last_response = None

        for attempt in range(self._max_retries):
            try:
                response = await self._client.request(method, url, **kwargs)

                # Success or non-retryable status
                if response.status_code not in retry_status_codes:
                    return response

                last_response = response
                last_error = f"Status {response.status_code}"
                logger.warning(
                    f"Request returned {response.status_code} "
                    f"(attempt {attempt + 1}/{self._max_retries})"
                )

            except (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError) as exc:
                last_error = str(exc)
                logger.warning(f"Request failed: {exc} (attempt {attempt + 1}/{self._max_retries})")

                if isinstance(exc, httpx.RemoteProtocolError):
                    # Try to reconnect
                    await self.close()
                    await self.connect()

            # Exponential backoff with jitter
            if attempt < self._max_retries - 1:
                backoff = (2**attempt) + (asyncio.get_event_loop().time() % 1)
                await asyncio.sleep(min(backoff, 30.0))  # Max 30 seconds

        # All retries exhausted
        if last_response is not None:
            return last_response  # Return last response even if error status

        raise RequestError(f"Request failed after {self._max_retries} attempts: {last_error}")

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        """GET request"""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        """POST request"""
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> httpx.Response:
        """PUT request"""
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> httpx.Response:
        """DELETE request"""
        return await self.request("DELETE", url, **kwargs)

    async def patch(self, url: str, **kwargs: Any) -> httpx.Response:
        """PATCH request"""
        return await self.request("PATCH", url, **kwargs)

    async def stream(
        self, method: str, url: str, chunk_size: int = 65536, **kwargs: Any
    ) -> AsyncIterator[bytes]:
        """
        Stream response data in chunks (Starlette pattern).
        Memory-efficient for large responses.

        Args:
            method: HTTP method
            url: Request URL
            chunk_size: Chunk size in bytes (default 64KB)
            **kwargs: Additional request parameters

        Yields:
            bytes: Response chunks
        """
        if not self._client:
            await self.connect()
        if self._client is None:
            raise RuntimeError("HTTP client is not connected")

        try:
            async with self._client.stream(method, url, **kwargs) as response:
                response.raise_for_status()
                async for chunk in response.aiter_bytes(chunk_size=chunk_size):
                    yield chunk
        except httpx.RemoteProtocolError as exc:
            raise ClientDisconnect(f"Connection lost during streaming: {exc}") from exc

    @asynccontextmanager
    async def stream_context(self, method: str, url: str, **kwargs: Any):
        """
        Context manager for streaming responses.
        Provides direct access to response object.
        """
        if not self._client:
            await self.connect()
        if self._client is None:
            raise RuntimeError("HTTP client is not connected")

        async with self._client.stream(method, url, **kwargs) as response:
            yield response

    async def download(
        self, url: str, file_path: str, chunk_size: int = 65536, **kwargs: Any
    ) -> int:
        """
        Download file efficiently with streaming.

        Returns:
            int: Total bytes downloaded
        """
        import aiofiles

        total_bytes = 0
        async with aiofiles.open(file_path, "wb") as f:
            async for chunk in self.stream("GET", url, chunk_size=chunk_size, **kwargs):
                await f.write(chunk)
                total_bytes += len(chunk)

        return total_bytes
