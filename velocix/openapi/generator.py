"""OpenAPI specification generator"""

import json
from pathlib import Path
from typing import Any

from .decorators import get_operation_for_function
from .models import Info, OpenAPISpec, PathItem, SecurityScheme, Server
from .models import Tag as TagModel

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore


class OpenAPIGenerator:
    """Generate OpenAPI specifications from decorated routes"""

    def __init__(
        self,
        title: str,
        version: str = "1.0.0",
        description: str | None = None,
        servers: list[dict[str, Any]] | None = None,
    ):
        self.title = title
        self.version = version
        self.description = description
        self.servers = servers or [{"url": "/", "description": "Default server"}]
        self.security_schemes: dict[str, SecurityScheme] = {}
        self.global_tags: list[TagModel] = []

    def add_security_scheme(
        self,
        name: str,
        type_: str,
        scheme: str | None = None,
        bearer_format: str | None = None,
        description: str | None = None,
    ) -> None:
        """Add a security scheme"""
        self.security_schemes[name] = SecurityScheme(
            type=type_, scheme=scheme, bearer_format=bearer_format, description=description
        )

    def add_tag(self, name: str, description: str | None = None) -> None:
        """Add a global tag"""
        tag = TagModel(name=name, description=description)
        if tag not in self.global_tags:
            self.global_tags.append(tag)

    def generate_from_router(self, router: Any) -> OpenAPISpec:
        """Generate OpenAPI spec from a Velocix router"""
        paths: dict[str, PathItem] = {}

        # Extract static routes
        if hasattr(router, "static_routes"):
            for method, routes in router.static_routes.items():
                for path, handler in routes.items():
                    self._add_path_from_handler(paths, path, method.lower(), handler)

        # Extract dynamic routes
        if hasattr(router, "dynamic_patterns"):
            for pattern_tuple in router.dynamic_patterns:
                # pattern_tuple format: (method, path_pattern, handler, params, ...)
                if len(pattern_tuple) >= 3:
                    method = pattern_tuple[0]
                    path = pattern_tuple[1]
                    handler = pattern_tuple[2]
                    self._add_path_from_handler(paths, path, method.lower(), handler)

        # Also check route_cache for any additional routes
        if hasattr(router, "route_cache"):
            for method, routes in router.route_cache.items():
                for path, cached_route in routes.items():
                    handler = cached_route.handler
                    self._add_path_from_handler(paths, path, method.lower(), handler)

        return OpenAPISpec(
            openapi="3.1.0",
            info=Info(title=self.title, version=self.version, description=self.description),
            servers=[Server(**server) for server in self.servers],
            paths=paths,
            components={
                "securitySchemes": {
                    name: scheme.to_dict() for name, scheme in self.security_schemes.items()
                }
            }
            if self.security_schemes
            else None,
            tags=self.global_tags,
        )

    def _add_path_from_handler(
        self, paths: dict[str, PathItem], path: str, method: str, handler: Any
    ) -> None:
        """Add a path to the paths dict from handler info"""
        if not handler or not path:
            return

        # Get operation from handler or create default
        operation = get_operation_for_function(handler)
        if not operation:
            # Auto-generate operation from function
            from .auto_docs import generate_operation_from_function

            operation = generate_operation_from_function(handler, path, method.upper())

        # Ensure path exists
        if path not in paths:
            paths[path] = PathItem()

        # Set operation for method
        setattr(paths[path], method, operation)

    def _extract_path_from_key(self, key: str) -> str | None:
        """Extract path from operation key (simplified)"""
        # This is a placeholder - in real implementation,
        # you'd need to map function names to actual paths
        parts = key.split(".")
        if len(parts) >= 2:
            return f"/{parts[-1]}"
        return None

    def to_dict(self, router: Any) -> dict[str, Any]:
        """Convert to dictionary"""
        spec = self.generate_from_router(router)
        return spec.to_dict()

    def to_json(self, router: Any, indent: int = 2) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(router), indent=indent)

    def to_yaml(self, router: Any) -> str:
        """Convert to YAML string"""
        if yaml is None:
            raise ImportError("PyYAML is required for YAML export")
        return str(yaml.dump(self.to_dict(router), default_flow_style=False))

    def save_json(self, router: Any, file_path: str | Path, indent: int = 2) -> None:
        """Save as JSON file"""
        path = Path(file_path)
        path.write_text(self.to_json(router, indent))

    def save_yaml(self, router: Any, file_path: str | Path) -> None:
        """Save as YAML file"""
        path = Path(file_path)
        path.write_text(self.to_yaml(router))


SWAGGER_JS_URL = "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/swagger-ui-bundle.js"
SWAGGER_JS_SRI = "sha384-wmyclcVGX/WhUkdkATwhaK1X1JtiNrr2EoYJ+diV3vj4v6OC5yCeSu+yW13SYJep"
SWAGGER_CSS_URL = "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/swagger-ui.css"
SWAGGER_CSS_SRI = "sha384-wxLW6kwyHktdDGr6Pv1zgm/VGJh99lfUbzSn6HNHBENZlCN7W602k9VkGdxuFvPn"
REDOC_JS_URL = "https://cdn.jsdelivr.net/npm/redoc@2.1.5/bundles/redoc.standalone.js"
REDOC_JS_SRI = "sha384-0GrsyTQc9Oqd8h+b2dbc4XdR2T/DYpy0tLNNstyx+LBMUyiBbcWPbEs9aRmUcaxD"


class SwaggerUIHandler:
    """Serve Swagger UI for OpenAPI documentation"""

    def __init__(
        self,
        openapi_url: str = "/openapi.json",
        title: str = "API Documentation",
        swagger_js_url: str = SWAGGER_JS_URL,
        swagger_css_url: str = SWAGGER_CSS_URL,
        swagger_js_sri: str | None = SWAGGER_JS_SRI,
        swagger_css_sri: str | None = SWAGGER_CSS_SRI,
    ):
        self.openapi_url = openapi_url
        self.title = title
        self.swagger_js_url = swagger_js_url
        self.swagger_css_url = swagger_css_url

    def get_html(self) -> str:
        """Generate Swagger UI HTML"""
        return f"""
<!DOCTYPE html>
<html>
<head>
    <title>{self.title}</title>
    <link rel="stylesheet" type="text/css" href="{self.swagger_css_url}" />
    <style>
        html {{
            box-sizing: border-box;
            overflow: -moz-scrollbars-vertical;
            overflow-y: scroll;
        }}
        *, *:before, *:after {{
            box-sizing: inherit;
        }}
        body {{
            margin:0;
            background: #fafafa;
        }}
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="{self.swagger_js_url}"></script>
    <script>
        window.onload = function() {{
            const ui = SwaggerUIBundle({{
                url: '{self.openapi_url}',
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIBundle.presets.standalone
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout"
            }});
        }};
    </script>
</body>
</html>
        """.strip()


class ReDocHandler:
    """Serve ReDoc for OpenAPI documentation"""

    def __init__(
        self,
        openapi_url: str = "/openapi.json",
        title: str = "API Documentation",
        redoc_js_url: str = "https://unpkg.com/redoc@2.1.3/bundles/redoc.standalone.js",
    ):
        self.openapi_url = openapi_url
        self.title = title
        self.redoc_js_url = redoc_js_url

    def get_html(self) -> str:
        """Generate ReDoc HTML"""
        return f"""
<!DOCTYPE html>
<html>
<head>
    <title>{self.title}</title>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://fonts.googleapis.com/css?family=Montserrat:300,400,700|Roboto:300,400,700" rel="stylesheet">
    <style>
        body {{
            margin: 0;
            padding: 0;
        }}
    </style>
</head>
<body>
    <redoc spec-url='{self.openapi_url}'></redoc>
    <script src="{self.redoc_js_url}"></script>
</body>
</html>
        """.strip()


# Convenience functions for quick setup
def create_openapi_generator(
    title: str, version: str = "1.0.0", description: str | None = None
) -> OpenAPIGenerator:
    """Create an OpenAPI generator with common defaults"""
    return OpenAPIGenerator(title=title, version=version, description=description)


def setup_docs_routes(router: Any, generator: OpenAPIGenerator) -> None:
    """Set up documentation routes on a router"""
    swagger_handler = SwaggerUIHandler()
    redoc_handler = ReDocHandler()

    # Add OpenAPI JSON endpoint
    def openapi_json() -> dict[str, Any]:
        return generator.to_dict(router)

    # Add Swagger UI endpoint
    def swagger_ui() -> str:
        return swagger_handler.get_html()

    # Add ReDoc endpoint
    def redoc_ui() -> str:
        return redoc_handler.get_html()

    # Register routes (this depends on your router implementation)
    if hasattr(router, "get"):
        router.get("/openapi.json", openapi_json)
        router.get("/docs", swagger_ui)
        router.get("/redoc", redoc_ui)
    elif hasattr(router, "route"):
        router.route("/openapi.json", ["GET"], openapi_json)
        router.route("/docs", ["GET"], swagger_ui)
        router.route("/redoc", ["GET"], redoc_ui)
