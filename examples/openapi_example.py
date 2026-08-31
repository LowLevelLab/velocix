"""
Comprehensive OpenAPI Auto-Documentation Example for Velocix

This example demonstrates proper parameter categorization following OpenAPI 3.0 spec:
- Path parameters: In URL path like /users/{user_id}
- Query parameters: Scalar types with defaults, passed as ?key=value
- Request body: Complex types (Structs/models) for POST/PUT/PATCH

Following FastAPI's approach for automatic OpenAPI generation.
"""
from velocix import Velocix
from velocix.core.depends import Depends
from velocix.openapi import enable_auto_docs
from velocix.validation import Struct


# Data models using msgspec Struct (Velocix's validation system)
class User(Struct):
    """User data model"""
    id: int
    name: str
    email: str
    age: int = 18  # Optional with default


class CreateUserRequest(Struct):
    """Request body for creating a user"""
    name: str
    email: str
    age: int = 18


class UpdateUserRequest(Struct):
    """Request body for updating a user"""
    name: str | None = None
    email: str | None = None
    age: int | None = None


class Post(Struct):
    """Blog post model"""
    id: int
    user_id: int
    title: str
    content: str
    published: bool = False


# Dependency injection examples
async def get_current_user(request):
    """Dependency: Get current authenticated user"""
    # In real app, verify token, get user from DB, etc.
    return {"user_id": 1, "username": "john_doe"}


async def get_database(request):
    """Dependency: Get database connection"""
    # In real app, return actual DB connection
    return {"connection": "postgresql://localhost/mydb"}


# Create Velocix app
app = Velocix()


# ============================================================================
# GET ENDPOINTS - Query and Path Parameters Only
# ============================================================================

@app.get("/")
async def root():
    """
    Root endpoint
    
    OpenAPI Result:
    - No parameters
    - Returns 200 response
    """
    return {"message": "Welcome to Velocix API"}


@app.get("/users")
async def list_users(
    skip: int = 0,          # Query param with default
    limit: int = 10,        # Query param with default
    search: str = None,     # Optional query param
    sort: str = "created"   # Query param with default
):
    """
    List all users with pagination and filtering
    
    OpenAPI Result:
    - All parameters become 'query' parameters (in: query)
    - skip, limit, search, sort all in query string
    - No requestBody (GET method)
    
    Example: GET /users?skip=0&limit=10&search=john&sort=name
    """
    return {
        "users": [
            {"id": 1, "name": "John Doe", "email": "john@example.com"},
            {"id": 2, "name": "Jane Smith", "email": "jane@example.com"}
        ],
        "pagination": {"skip": skip, "limit": limit},
        "filters": {"search": search, "sort": sort}
    }


@app.get("/users/{user_id}")
async def get_user(user_id: int):
    """
    Get a specific user by ID
    
    OpenAPI Result:
    - user_id is a 'path' parameter (in: path, required: true)
    - No query parameters
    - No requestBody (GET method)
    
    Example: GET /users/123
    """
    return {
        "id": user_id,
        "name": "John Doe",
        "email": "john@example.com",
        "age": 30
    }


@app.get("/users/{user_id}/posts")
async def get_user_posts(
    user_id: int,           # Path parameter (in URL)
    published: bool = None, # Query parameter
    limit: int = 10         # Query parameter
):
    """
    Get posts for a specific user
    
    OpenAPI Result:
    - user_id: path parameter (in: path)
    - published, limit: query parameters (in: query)
    - No requestBody (GET method)
    
    Example: GET /users/123/posts?published=true&limit=20
    """
    return {
        "user_id": user_id,
        "posts": [
            {"id": 1, "title": "First Post", "published": True},
            {"id": 2, "title": "Second Post", "published": False}
        ],
        "filters": {"published": published, "limit": limit}
    }


# ============================================================================
# POST ENDPOINTS - Path/Query Parameters + Request Body
# ============================================================================

@app.post("/users")
async def create_user(user: CreateUserRequest):
    """
    Create a new user
    
    OpenAPI Result:
    - NO parameters array (user is not in query or path)
    - HAS requestBody with CreateUserRequest schema
    - Content-Type: application/json
    - Schema includes: name (required), email (required), age (optional, default: 18)
    
    Example Request:
    POST /users
    Content-Type: application/json
    {
        "name": "John Doe",
        "email": "john@example.com",
        "age": 30
    }
    """
    return {
        "id": 123,
        "name": user.name,
        "email": user.email,
        "age": user.age,
        "created": True
    }


@app.post("/users/{user_id}/posts")
async def create_post(
    user_id: int,           # Path parameter
    post: Post,             # Request body
    notify: bool = False    # Query parameter
):
    """
    Create a post for a specific user
    
    OpenAPI Result:
    - user_id: path parameter (in: path, required: true)
    - notify: query parameter (in: query, required: false)
    - post: requestBody with Post schema (NOT in parameters)
    
    This demonstrates proper separation:
    - Path params in URL: /users/123/posts
    - Query params in query string: ?notify=true
    - Body params in request body: {"title": "...", "content": "..."}
    
    Example Request:
    POST /users/123/posts?notify=true
    Content-Type: application/json
    {
        "id": 1,
        "user_id": 123,
        "title": "My First Post",
        "content": "This is the content",
        "published": false
    }
    """
    return {
        "id": post.id,
        "user_id": user_id,
        "title": post.title,
        "content": post.content,
        "published": post.published,
        "notification_sent": notify
    }


# ============================================================================
# PUT ENDPOINTS - Update Resources
# ============================================================================

@app.put("/users/{user_id}")
async def update_user(
    user_id: int,                    # Path parameter
    user: UpdateUserRequest          # Request body
):
    """
    Update a user's information
    
    OpenAPI Result:
    - user_id: path parameter
    - user: requestBody with UpdateUserRequest schema
    - All fields in UpdateUserRequest are optional
    
    Example Request:
    PUT /users/123
    Content-Type: application/json
    {
        "name": "John Updated",
        "email": "john.new@example.com"
    }
    """
    return {
        "id": user_id,
        "name": user.name,
        "email": user.email,
        "age": user.age,
        "updated": True
    }


# ============================================================================
# PATCH ENDPOINTS - Partial Updates
# ============================================================================

@app.patch("/users/{user_id}")
async def partial_update_user(
    user_id: int,                    # Path parameter
    updates: dict                    # Request body (generic dict)
):
    """
    Partially update a user
    
    OpenAPI Result:
    - user_id: path parameter
    - updates: requestBody with generic object schema (dict type)
    
    Example Request:
    PATCH /users/123
    Content-Type: application/json
    {
        "name": "New Name"
    }
    """
    return {
        "id": user_id,
        "updated_fields": updates,
        "success": True
    }


# ============================================================================
# DELETE ENDPOINTS - Path Parameters Only
# ============================================================================

@app.delete("/users/{user_id}")
async def delete_user(user_id: int):
    """
    Delete a user
    
    OpenAPI Result:
    - user_id: path parameter
    - No query parameters
    - No requestBody (DELETE typically doesn't have body)
    - Response: 204 No Content
    
    Example: DELETE /users/123
    """
    return {"deleted": True, "user_id": user_id}


# ============================================================================
# DEPENDENCY INJECTION EXAMPLES
# ============================================================================

@app.get("/me")
async def get_current_user_info(
    current_user = Depends(get_current_user)  # Dependency, not a parameter
):
    """
    Get current authenticated user's info
    
    OpenAPI Result:
    - current_user is NOT in parameters (it's a dependency)
    - No parameters at all
    - Dependencies are internal, not exposed in OpenAPI
    
    Example: GET /me
    """
    return {
        "user": current_user,
        "authenticated": True
    }


@app.post("/users/batch")
async def create_users_batch(
    users: list[CreateUserRequest],     # Request body (array)
    db = Depends(get_database)          # Dependency (not in OpenAPI)
):
    """
    Create multiple users at once
    
    OpenAPI Result:
    - db is NOT in parameters or requestBody (dependency)
    - users: requestBody with array schema
    - Schema: array of CreateUserRequest objects
    
    Example Request:
    POST /users/batch
    Content-Type: application/json
    [
        {"name": "User 1", "email": "user1@example.com"},
        {"name": "User 2", "email": "user2@example.com"}
    ]
    """
    return {
        "created": len(users),
        "database": db["connection"],
        "users": [
            {"id": i, "name": user.name, "email": user.email}
            for i, user in enumerate(users, 1)
        ]
    }


# ============================================================================
# COMPLEX EXAMPLES - Mixed Parameters
# ============================================================================

@app.post("/users/{user_id}/avatar")
async def upload_avatar(
    user_id: int,               # Path parameter
    avatar_data: dict,          # Request body
    format: str = "png",        # Query parameter
    resize: bool = True         # Query parameter
):
    """
    Upload user avatar with processing options
    
    OpenAPI Result:
    - user_id: path parameter (in: path)
    - format, resize: query parameters (in: query)
    - avatar_data: requestBody (application/json)
    
    Example Request:
    POST /users/123/avatar?format=jpeg&resize=false
    Content-Type: application/json
    {
        "data": "base64_encoded_image_data",
        "width": 200,
        "height": 200
    }
    """
    return {
        "user_id": user_id,
        "avatar_uploaded": True,
        "format": format,
        "resized": resize,
        "size": avatar_data.get("width", 0)
    }


# Enable automatic OpenAPI documentation
enable_auto_docs(
    app,
    title="Velocix API with Proper OpenAPI",
    version="1.0.0",
    description="""
    # Velocix OpenAPI Example
    
    This API demonstrates proper OpenAPI 3.0 parameter handling:
    
    ## Parameter Types
    
    ### Path Parameters
    - In the URL path: `/users/{user_id}`
    - Always required
    - OpenAPI: `in: path`
    
    ### Query Parameters
    - In the query string: `?skip=0&limit=10`
    - Usually optional with defaults
    - Scalar types (str, int, bool)
    - OpenAPI: `in: query`
    
    ### Request Body
    - In POST/PUT/PATCH request body
    - Complex types (Structs, models, dicts)
    - Content-Type: application/json
    - OpenAPI: `requestBody` object (NOT in parameters array)
    
    ## Key Principles
    
    1. **Separation**: Path/query params go in `parameters[]`, body data goes in `requestBody`
    2. **Method-specific**: GET/DELETE use parameters only, POST/PUT/PATCH can have requestBody
    3. **Type-based**: Scalar types → query params, Complex types → request body
    4. **Dependencies**: Dependency injection params are internal, not in OpenAPI
    
    ## Examples
    
    - GET with query params: `/users?skip=0&limit=10`
    - GET with path param: `/users/123`
    - POST with body: `POST /users` + JSON body
    - POST with mixed: `POST /users/123/posts?notify=true` + JSON body
    """,
    openapi_url="/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc"
)


if __name__ == "__main__":
    print("=" * 80)
    print("Velocix OpenAPI Auto-Documentation Example")
    print("=" * 80)
    print()
    print("This example demonstrates proper OpenAPI 3.0 parameter handling:")
    print()
    print("1. Path Parameters:")
    print("   - /users/{user_id} → user_id is 'in: path'")
    print()
    print("2. Query Parameters:")
    print("   - ?skip=0&limit=10 → skip, limit are 'in: query'")
    print()
    print("3. Request Body:")
    print("   - POST/PUT/PATCH with JSON → 'requestBody' object")
    print("   - Complex types (Structs) become request body, NOT parameters")
    print()
    print("4. Separation:")
    print("   - Parameters array: path + query only")
    print("   - Request body: separate 'requestBody' object")
    print("   - Never mixed!")
    print()
    print("=" * 80)
    print()
    print("Start the server and visit:")
    print("  - http://localhost:8000/docs     (Swagger UI)")
    print("  - http://localhost:8000/redoc    (ReDoc)")
    print("  - http://localhost:8000/openapi.json (Raw OpenAPI spec)")
    print()
    
    # Note: Run with: python -m velocix examples.openapi_example:app
    # Or with uvicorn: uvicorn examples.openapi_example:app --reload
