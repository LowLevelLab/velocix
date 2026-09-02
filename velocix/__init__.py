"""
Velocix Framework - ASGI web framework built to understand async Python patterns.

Built on top of:
- Granian (Rust ASGI server)
- orjson (Rust JSON serialization)
- httptools (C HTTP parsing)
- msgspec (Rust-speed validation)
- Radix tree routing with advanced caching
"""

__version__ = "0.1.3"
__author__ = "Velocix Team"
__description__ = "ASGI web framework with automatic OpenAPI documentation"

# Framework capabilities
__features__ = [
    "Automatic OpenAPI 3.1 documentation generation",
    "Zero-decorator auto-docs from function signatures",
    "Intuitive decorator-style syntax",
    "JWT-based authentication",
    "Secure password hashing",
    "Advanced middleware system",
    "WebSocket support",
    "Built-in HTTP client",
    "Comprehensive testing utilities",
    "Type-safe validation",
    "CORS and rate limiting",
    "Streaming responses and file serving",
    "Server-sent events (SSE)",
]

from functools import partial

from velocix.core.app import Velocix, cache_response
from velocix.core.depends import Depends
from velocix.core.exceptions import HTTPException, NoMatchFound
from velocix.core.middleware import BaseMiddleware, SessionMiddleware
from velocix.core.params import Cookie, File, Form, Header, Query
from velocix.core.request import Request
from velocix.core.response import (
    EventStreamResponse,
    FileResponse,
    HTMLResponse,
    JSONLinesResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
from velocix.core.router import Router
from velocix.core.staticfiles import StaticFiles

# HTTP Client
from velocix.http.client import HTTPClient
from velocix.http.multipart import MultipartForm, UploadFile

# OpenAPI and Documentation
from velocix.openapi.auto_docs import enable_auto_docs
from velocix.openapi.decorators import operation, parameter, response
from velocix.openapi.generator import OpenAPIGenerator
from velocix.security.cors import CORSMiddleware

# Security
from velocix.security.jwt import JWTHandler, JWTManager
from velocix.security.password import PasswordHasher, PasswordManager
from velocix.security.ratelimit import ProductionRateLimiter, RateLimitMiddleware
from velocix.testing.client import TestClient
from velocix.websocket.connection import WebSocket, WebSocketManager


def create_app(
    title: str = "Velocix API",
    version: str = __version__,
    description: str = "High-performance API built with Velocix",
    auto_docs: bool = True,
    cors: bool = False,
    rate_limit: bool = False,
) -> Velocix:
    """
    Create a pre-configured Velocix application with common features

    Args:
        title: API title for documentation
        version: API version
        description: API description
        auto_docs: Enable automatic OpenAPI documentation
        cors: Enable CORS middleware
        rate_limit: Enable rate limiting

    Returns:
        Configured Velocix application
    """
    app = Velocix()

    if auto_docs:
        enable_auto_docs(app, title=title, version=version, description=description)

    if cors:
        app.add_middleware(
            partial(
                CORSMiddleware,
                allow_origins=["*"],
                allow_credentials=True,
                allow_methods=["*"],
                allow_headers=["*"],
            )
        )

    if rate_limit:
        limiter = ProductionRateLimiter()
        limiter.set_global_window(limit=100, window_size=60)
        app.add_middleware(partial(RateLimitMiddleware, limiter=limiter))

    return app


__all__ = [
    # Core
    "Velocix",
    "cache_response",
    "Request",
    "Response",
    "JSONResponse",
    "HTMLResponse",
    "Router",
    "HTTPException",
    "NoMatchFound",
    "BaseMiddleware",
    "Depends",
    "SessionMiddleware",
    # Responses
    "StreamingResponse",
    "FileResponse",
    "EventStreamResponse",
    "JSONLinesResponse",
    "PlainTextResponse",
    "RedirectResponse",
    # OpenAPI & Documentation
    "enable_auto_docs",
    "OpenAPIGenerator",
    "operation",
    "parameter",
    "response",
    # Parameter markers
    "Query",
    "Header",
    "Cookie",
    "Form",
    "File",
    # Uploads
    "UploadFile",
    "MultipartForm",
    # Static files
    "StaticFiles",
    # Security
    "JWTManager",
    "JWTHandler",
    "PasswordManager",
    "PasswordHasher",
    "CORSMiddleware",
    "RateLimitMiddleware",
    # HTTP & WebSocket
    "HTTPClient",
    "WebSocket",
    "WebSocketManager",
    # Testing
    "TestClient",
    # Utilities
    "create_app",
]
