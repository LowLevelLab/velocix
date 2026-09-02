"""OpenAPI support for Velocix"""

from .auto_docs import (
    auto_document_function,
    enable_auto_docs,
    generate_operation_from_function,
)
from .decorators import (
    array_schema,
    clear_operations,
    get_operation_for_function,
    integer_schema,
    object_schema,
    operation,
    parameter,
    request_body,
    response,
    security,
    string_schema,
    tag,
)
from .generator import (
    OpenAPIGenerator,
    ReDocHandler,
    create_openapi_generator,
    setup_docs_routes,
)
from .models import (
    Info,
    OpenAPISpec,
    Operation,
    Parameter,
    ParameterIn,
    PathItem,
    Response,
    Schema,
    SchemaType,
    SecurityScheme,
    Server,
    Tag,
)

__all__ = [
    # Models
    "OpenAPISpec",
    "Info",
    "Server",
    "PathItem",
    "Operation",
    "Parameter",
    "Response",
    "Schema",
    "Tag",
    "SecurityScheme",
    "ParameterIn",
    "SchemaType",
    # Decorators (low-level)
    "operation",
    "parameter",
    "response",
    "tag",
    "request_body",
    "security",
    "get_operation_for_function",
    "clear_operations",
    # Schema helpers
    "string_schema",
    "integer_schema",
    "array_schema",
    "object_schema",
    # Generator
    "OpenAPIGenerator",
    "ReDocHandler",
    "create_openapi_generator",
    "setup_docs_routes",
    # Auto-documentation (zero decorators!)
    "enable_auto_docs",
    "auto_document_function",
    "generate_operation_from_function",
]
