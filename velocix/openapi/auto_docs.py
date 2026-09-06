"""Automatic OpenAPI generation from function signatures"""

import inspect
from typing import Any, get_origin, get_type_hints

from ..core.depends import Depends
from .decorators import _route_operations
from .models import Operation, Parameter, ParameterIn, Response, Schema, SchemaType

# HTTP methods that support request body (following OpenAPI 3.0 spec)
METHODS_WITH_BODY = {"POST", "PUT", "PATCH"}


def python_type_to_schema_type(py_type: Any) -> SchemaType:
    """Convert Python type to OpenAPI schema type"""
    if py_type is str:
        return SchemaType.STRING
    elif py_type is int:
        return SchemaType.INTEGER
    elif py_type is float:
        return SchemaType.NUMBER
    elif py_type is bool:
        return SchemaType.BOOLEAN
    elif py_type is list or get_origin(py_type) is list:
        return SchemaType.ARRAY
    elif py_type is dict or get_origin(py_type) is dict:
        return SchemaType.OBJECT
    else:
        return SchemaType.STRING  # Default fallback


def is_msgspec_struct(annotation: Any) -> bool:
    """Check if annotation is a msgspec Struct (Velocix's validation model)"""
    try:
        # Check for msgspec.Struct
        import msgspec

        if hasattr(annotation, "__mro__"):
            return msgspec.Struct in annotation.__mro__
    except (ImportError, AttributeError):
        pass
    return False


def is_body_parameter(param_name: str, param: inspect.Parameter, annotation: Any) -> bool:
    """
    Determine if a parameter should be treated as request body.

    Following FastAPI's logic:
    - Parameters with Depends() are dependencies, not body
    - Parameters named 'request' are request objects, not body
    - Path parameters are in the URL path, not body
    - Query parameters have default values and scalar types
    - Body parameters are typically Pydantic models or msgspec Structs
    """
    # Check if it's a dependency injection
    if isinstance(param.default, Depends):
        return False

    # Check if it's the request object
    if param_name.lower() == "request":
        return False

    # If annotation is a Struct, it's a body parameter
    if is_msgspec_struct(annotation):
        return True

    # Complex types without default values are likely body params
    if param.default == inspect.Parameter.empty:
        origin = get_origin(annotation)
        # Dict, List (without default) are likely body params
        if origin in (dict, list) or annotation in (dict, list, dict, list):
            return True

    return False


def is_scalar_type(annotation: Any) -> bool:
    """Check if type is scalar (str, int, float, bool)"""
    return annotation in (str, int, float, bool, type(None))


def extract_path_parameters(path: str) -> list[str]:
    """Extract parameter names from path like /users/{user_id}"""
    import re

    return re.findall(r"\{(\w+)\}", path)


def _rewrite_defs_refs(node: Any) -> None:
    """Rewrite msgspec's "#/$defs/X" refs to OpenAPI's "#/components/schemas/X", in place."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str) and value.startswith("#/$defs/"):
                node[key] = value.replace("#/$defs/", "#/components/schemas/", 1)
            else:
                _rewrite_defs_refs(value)
    elif isinstance(node, list):
        for item in node:
            _rewrite_defs_refs(item)


def generate_schema_from_struct(struct_class: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Generate an OpenAPI schema from a msgspec Struct.

    Uses msgspec's native JSON schema generation for best compatibility.
    Falls back to manual inspection if JSON schema generation fails.

    Returns (schema, defs): schema is what goes in the requestBody, and defs
    is the {StructName: schema} map the caller must merge into the document's
    top-level components.schemas so schema's "$ref" (rewritten to
    "#/components/schemas/...") actually resolves.
    """
    try:
        import msgspec

        # Try using msgspec's native JSON schema generation
        # This is the most accurate and handles all msgspec features
        try:
            # msgspec.json.schema generates a complete JSON Schema: a
            # {"$ref": "#/$defs/Name", "$defs": {"Name": {...}, ...}} pair,
            # even for a single non-nested struct.
            schema = msgspec.json.schema(struct_class)

            # Convert to plain dict (schema returns a dict-like object)
            if hasattr(schema, "__dict__"):
                schema = vars(schema)
            elif not isinstance(schema, dict):
                schema = dict(schema)

            # $defs must be hoisted into the document's components.schemas
            # (by the caller) rather than dropped: schema's $ref depends on
            # it, and deleting it here left the $ref dangling.
            defs = schema.pop("$defs", None) or {}

            # Remove schema metadata that's not needed
            if "$schema" in schema:
                del schema["$schema"]

            _rewrite_defs_refs(schema)
            _rewrite_defs_refs(defs)

            return schema, defs

        except Exception:
            # Fallback to manual inspection using __struct_fields__
            pass

        # Manual inspection fallback
        schema_props = {}
        required_fields = []

        if hasattr(struct_class, "__struct_fields__"):
            # Use msgspec.inspect for detailed type information
            try:
                from msgspec import inspect as msg_inspect

                type_info = msg_inspect.type_info(struct_class)

                if hasattr(type_info, "fields"):
                    for field in type_info.fields:
                        # Build property schema from field info
                        field_schema = _build_schema_from_type_info(field.type)
                        schema_props[field.name] = field_schema

                        # Check if required
                        if field.required:
                            required_fields.append(field.name)
            except Exception:
                # Final fallback: basic annotation inspection
                for field_name in struct_class.__struct_fields__:
                    field_type = struct_class.__annotations__.get(field_name, Any)

                    # Convert type to schema
                    schema_props[field_name] = {
                        "type": python_type_to_schema_type(field_type).value
                    }

                    # Check if field is required (no default value on class)
                    # In msgspec, fields without defaults are required
                    try:
                        getattr(struct_class, field_name)
                    except AttributeError:
                        required_fields.append(field_name)

        schema = {"type": "object", "properties": schema_props}

        if required_fields:
            schema["required"] = required_fields

        # Add description from docstring if available
        if struct_class.__doc__:
            schema["description"] = struct_class.__doc__.strip()

        return schema, {}

    except Exception:
        # Ultimate fallback to generic object schema
        return {"type": "object"}, {}


def _build_schema_from_type_info(type_info: Any) -> dict[str, Any]:
    """
    Build OpenAPI schema from msgspec.inspect type info.

    Handles various msgspec type info objects and converts them to
    OpenAPI-compatible schema dictionaries.
    """
    try:
        # Get type name
        type_name = type(type_info).__name__

        # Map msgspec type info to OpenAPI schema
        if type_name == "StrType":
            schema: dict[str, Any] = {"type": "string"}
            if hasattr(type_info, "min_length") and type_info.min_length is not None:
                schema["minLength"] = type_info.min_length
            if hasattr(type_info, "max_length") and type_info.max_length is not None:
                schema["maxLength"] = type_info.max_length
            if hasattr(type_info, "pattern") and type_info.pattern is not None:
                schema["pattern"] = type_info.pattern
            return schema

        elif type_name == "IntType":
            schema = {"type": "integer"}
            if hasattr(type_info, "gt") and type_info.gt is not None:
                schema["exclusiveMinimum"] = type_info.gt
            if hasattr(type_info, "ge") and type_info.ge is not None:
                schema["minimum"] = type_info.ge
            if hasattr(type_info, "lt") and type_info.lt is not None:
                schema["exclusiveMaximum"] = type_info.lt
            if hasattr(type_info, "le") and type_info.le is not None:
                schema["maximum"] = type_info.le
            return schema

        elif type_name == "FloatType":
            schema = {"type": "number"}
            if hasattr(type_info, "gt") and type_info.gt is not None:
                schema["exclusiveMinimum"] = type_info.gt
            if hasattr(type_info, "ge") and type_info.ge is not None:
                schema["minimum"] = type_info.ge
            if hasattr(type_info, "lt") and type_info.lt is not None:
                schema["exclusiveMaximum"] = type_info.lt
            if hasattr(type_info, "le") and type_info.le is not None:
                schema["maximum"] = type_info.le
            return schema

        elif type_name == "BoolType":
            return {"type": "boolean"}

        elif type_name == "NoneType":
            return {"type": "null"}

        elif type_name == "ListType":
            schema = {"type": "array"}
            if hasattr(type_info, "item_type"):
                schema["items"] = _build_schema_from_type_info(type_info.item_type)
            if hasattr(type_info, "min_length") and type_info.min_length is not None:
                schema["minItems"] = type_info.min_length
            if hasattr(type_info, "max_length") and type_info.max_length is not None:
                schema["maxItems"] = type_info.max_length
            return schema

        elif type_name == "DictType":
            return {"type": "object"}

        elif type_name == "UnionType":
            # For unions, use anyOf
            if hasattr(type_info, "types"):
                schemas = [_build_schema_from_type_info(t) for t in type_info.types]
                return {"anyOf": schemas}
            return {"type": "object"}

        elif type_name == "StructType":
            # Recursively generate schema for nested struct, inlined (this is
            # itself the manual-inspection fallback, so no components.schemas
            # registry is available here to hoist $defs into).
            if hasattr(type_info, "cls"):
                schema, _defs = generate_schema_from_struct(type_info.cls)
                return schema
            return {"type": "object"}

        # Default fallback
        return {"type": "object"}

    except Exception:
        return {"type": "object"}


def generate_operation_from_function(
    func: Any,
    path: str,
    method: str,
    auto_tags: bool = True,
    schema_registry: dict[str, Any] | None = None,
) -> Operation:
    """
    Automatically generate OpenAPI operation from function signature.

    schema_registry, when given, receives every msgspec Struct schema this
    operation's request body depends on (keyed by struct name) so the caller
    can merge it into the document's top-level components.schemas.

    Follows FastAPI's approach:
    1. Separate path parameters, query parameters, and body parameters
    2. For POST/PUT/PATCH: Use requestBody for body params
    3. For GET/DELETE: Use parameters array only
    4. Never mix body data in parameters array
    """

    # Get function signature and type hints
    sig = inspect.signature(func)
    type_hints = {}
    try:
        type_hints = get_type_hints(func)
    except (NameError, AttributeError):
        # Handle cases where type hints can't be resolved
        pass

    # Extract path parameters from URL
    path_params = extract_path_parameters(path)

    # Categorize parameters following FastAPI's logic
    parameters = []  # OpenAPI parameters (path, query, header, cookie)
    body_params = []  # Request body parameters
    has_body_field = False

    for param_name, param in sig.parameters.items():
        # Skip request object parameter
        if param_name.lower() == "request":
            continue

        # Get parameter annotation
        annotation = type_hints.get(param_name, param.annotation)
        if annotation == inspect.Parameter.empty:
            annotation = str  # Default to string

        # Skip dependency injection parameters
        if isinstance(param.default, Depends):
            continue

        # Categorize parameter
        if param_name in path_params:
            # PATH PARAMETER - always in URL path
            param_type = annotation
            parameters.append(
                Parameter(
                    name=param_name,
                    in_=ParameterIn.PATH,
                    required=True,
                    description=f"Path parameter: {param_name}",
                    schema=Schema(type=python_type_to_schema_type(param_type)),
                )
            )

        elif is_body_parameter(param_name, param, annotation):
            # BODY PARAMETER - complex types go in request body
            body_params.append((param_name, annotation, param))
            has_body_field = True

        else:
            # QUERY PARAMETER - scalar types with defaults or explicit query params
            param_type = annotation
            parameters.append(
                Parameter(
                    name=param_name,
                    in_=ParameterIn.QUERY,
                    required=param.default == inspect.Parameter.empty,
                    description=f"Query parameter: {param_name}",
                    schema=Schema(
                        type=python_type_to_schema_type(param_type),
                        default=param.default if param.default != inspect.Parameter.empty else None,
                    ),
                )
            )

    # Read __route_*__ attrs (set by route decorator) or fall back to auto-gen
    summary = getattr(func, "__route_summary__", None)
    if summary is None:
        summary = func.__name__.replace("_", " ").title()

    description = getattr(func, "__route_description__", None)
    if description is None:
        description = inspect.getdoc(func)

    tags = getattr(func, "__route_tags__", None)
    if tags is None:
        tags = []
        if auto_tags and path != "/":
            parts = path.strip("/").split("/")
            if parts and parts[0]:
                tag = parts[0].replace("{", "").replace("}", "")
                if tag:
                    tags.append(tag)

    deprecated = getattr(func, "__route_deprecated__", False)
    security = getattr(func, "__route_security__", None)

    # Generate default responses
    route_status = getattr(func, "__route_status_code__", None)
    if route_status is not None:
        responses = {str(route_status): Response(description="Successful operation")}
    else:
        responses = {"200": Response(description="Successful operation")}
        if method.upper() == "POST":
            responses["201"] = Response(description="Created")
        elif method.upper() == "DELETE":
            responses["204"] = Response(description="No Content")

    # Add validation error response if there are body params
    if has_body_field or parameters:
        responses["422"] = Response(description="Validation Error")

    # Add common error responses
    if "400" not in responses:
        responses["400"] = Response(description="Bad Request")
    responses["404"] = Response(description="Not Found")
    responses["500"] = Response(description="Internal Server Error")

    operation_id = getattr(func, "__route_operation_id__", None) or func.__name__

    # Create operation with parameters
    operation = Operation(
        summary=summary,
        description=description,
        operation_id=operation_id,
        tags=tags,
        deprecated=deprecated,
        parameters=parameters,  # This contains path and query params only
        responses=responses,
        security=security,
    )

    # Add requestBody ONLY for POST, PUT, PATCH methods (OpenAPI 3.0 spec)
    # This is separate from parameters array
    if method.upper() in METHODS_WITH_BODY and has_body_field:
        # Build request body schema from body parameters
        if len(body_params) == 1:
            # Single body parameter
            param_name, annotation, param = body_params[0]

            # Generate schema based on type
            if is_msgspec_struct(annotation):
                schema, defs = generate_schema_from_struct(annotation)
                if schema_registry is not None:
                    schema_registry.update(defs)
            else:
                # Generic schema for dict/list/other types
                origin = get_origin(annotation)
                if origin in (dict, dict) or annotation in (dict, dict):
                    schema = {"type": "object"}
                elif origin in (list, list) or annotation in (list, list):
                    schema = {"type": "array", "items": {}}
                else:
                    schema = {"type": "object"}

            operation.request_body = {
                "required": param.default == inspect.Parameter.empty,
                "content": {"application/json": {"schema": schema}},
            }
        else:
            # Multiple body parameters - combine into single schema
            properties = {}
            required_fields = []

            for param_name, annotation, param in body_params:
                properties[param_name] = {"type": python_type_to_schema_type(annotation).value}
                if param.default == inspect.Parameter.empty:
                    required_fields.append(param_name)

            schema = {"type": "object", "properties": properties}
            if required_fields:
                schema["required"] = required_fields

            operation.request_body = {
                "required": bool(required_fields),
                "content": {"application/json": {"schema": schema}},
            }

    return operation


def auto_document_function(func: Any, path: str, method: str) -> Any:
    """Automatically document a function without decorators"""
    operation = generate_operation_from_function(func, path, method)

    # Store in global registry
    key = f"{func.__module__}.{func.__name__}"
    _route_operations[key] = operation

    # Add metadata to function
    func._openapi_key = key
    func._openapi_path = path
    func._openapi_method = method

    return func


# Integration with existing Velocix router
def enable_auto_docs(
    app: Any,
    title: str = "API Documentation",
    version: str = "1.0.0",
    description: str = "",
    openapi_url: str = "/openapi.json",
    docs_url: str = "/docs",
    redoc_url: str = "/redoc",
) -> Any:
    """Enable automatic documentation on existing app with built-in routes"""
    from ..core.response import HTMLResponse, JSONResponse
    from .generator import OpenAPIGenerator, ReDocHandler

    # Create OpenAPI generator
    generator = OpenAPIGenerator(title=title, version=version, description=description)

    # Add OpenAPI JSON endpoint
    @app.get(openapi_url)
    async def get_openapi_spec():
        """Get OpenAPI specification"""
        spec = generator.generate_from_router(app.router)
        return JSONResponse(spec.to_dict())

    # Add Swagger UI endpoint
    if docs_url:

        @app.get(docs_url)
        async def get_swagger_ui():
            """Interactive API documentation (Swagger UI)"""
            html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>{title} - Swagger UI</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui.css" />
    <style>
        html {{ box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }}
        *, *:before, *:after {{ box-sizing: inherit; }}
        body {{ margin:0; background: #fafafa; }}
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {{
            const ui = SwaggerUIBundle({{
                url: '{openapi_url}',
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "BaseLayout",
                filter: false
            }});
        }};
    </script>
</body>
</html>
            """
            return HTMLResponse(html)

    # Add ReDoc endpoint
    if redoc_url:

        @app.get(redoc_url)
        async def get_redoc():
            """Interactive API documentation (ReDoc)"""
            handler = ReDocHandler(openapi_url=openapi_url, title=f"{title} - ReDoc")
            return HTMLResponse(handler.get_html())

    return app

