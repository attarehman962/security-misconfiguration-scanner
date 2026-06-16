# Security Misconfiguration Scanner API - Beginner Learning Guide

This guide explains the concepts used in this FastAPI project in a beginner
friendly way. It is written for someone who understands basic Python, but is
still learning web APIs, FastAPI, Pydantic, project structure, exception
handling, testing, and deployment.

The goal is not only to explain what each file does, but also why the project is
organized this way.

## 1. What This App Is

This project is a small API for a security misconfiguration scanner.

An API is a program that receives requests from a client and returns responses.
The client can be:

- A frontend website
- A mobile app
- Another backend service
- A command line tool such as `curl`
- The automatic API docs at `/docs`

This app currently accepts a URL and returns a mock scan result. It does not yet
perform real network scanning. The current scanner response is fake data created
inside `app/services/scans.py`.

Example request:

```http
POST /api/v1/scans
Content-Type: application/json
```

Example JSON body:

```json
{
  "target_url": "https://example.com",
  "include_exposed_files": true
}
```

Important current behavior:

- `target_url` is validated by Pydantic as an HTTP or HTTPS URL.
- `include_exposed_files` is accepted by the request schema.
- `include_exposed_files` is not yet passed into the service, so it does not
  change the mock scan result yet.
- Unexpected server errors are hidden from the client but logged on the server.

## 2. Big Picture Flow

When a user creates a scan, the app flow is:

```txt
Client
  -> FastAPI app
  -> Router
  -> Pydantic request schema
  -> Dependency injection
  -> ScanService
  -> Pydantic response schema
  -> JSON response
```

In real file names:

```txt
app/main.py
  -> app/api/routes/scans.py
  -> app/schemas/scans.py
  -> app/api/dependencies.py
  -> app/services/scans.py
  -> app/schemas/scans.py
```

If something goes wrong:

```txt
Exception
  -> app/core/exceptions.py
  -> safe JSON error response
  -> server log keeps traceback
```

## 3. Web API Basics

HTTP APIs use methods and paths.

Common HTTP methods:

| Method | Meaning |
| --- | --- |
| `GET` | Read data |
| `POST` | Create something or start an action |
| `PUT` | Replace something |
| `PATCH` | Partially update something |
| `DELETE` | Delete something |

This app currently uses:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/health` | Check if the API is alive |
| `POST` | `/api/v1/scans` | Create a scan |
| `GET` | `/api/v1/scans` | List scans |
| `GET` | `/api/v1/scans/{scan_id}` | Get one scan |

HTTP responses include status codes.

Common status codes in this project:

| Status | Meaning |
| --- | --- |
| `200` | OK |
| `201` | Created |
| `400` | Bad request due to business rule |
| `404` | Resource not found |
| `422` | Validation error |
| `500` | Unexpected server error |

## 4. Why The Project Has Layers

The project is split into folders so each part has a clear job.

```txt
app/
  main.py          starts and configures the app
  api/            HTTP routes and dependencies
  core/           app-wide config and exception handling
  db/             database engine, session, and base class
  models/         database table models
  repositories/   database query and write functions
  schemas/        request and response data models
  services/       business logic
tests/            automated tests
```

This separation keeps the code easier to understand and easier to change.

Bad structure would put everything in one file:

```txt
main.py
  routes
  validation
  service logic
  error handling
  settings
  tests
```

That becomes hard to maintain.

Better structure separates responsibilities:

- Routes handle HTTP.
- Database code handles storage connections.
- Models describe database tables.
- Repositories read and write database records.
- Schemas handle data shape and validation.
- Services handle business behavior.
- Core handles app-wide setup.
- Tests verify behavior.

## 5. Full File And Folder Purpose

### `README.md`

The main project documentation.

It explains:

- What the app does
- How to run it
- How the folders work
- How requests flow
- How exceptions work
- How to deploy later

### `requirements.txt`

Lists Python dependencies.

Current dependencies include:

- `fastapi[standard]`
- `starlette<1.0`
- `pytest`
- `pydantic[email]`
- `httpx`

When someone creates a fresh virtual environment, they install these with:

```bash
python -m pip install -r requirements.txt
```

### `pytest.ini`

Configures pytest.

It tells pytest:

- Look for tests in `tests`
- Add the current directory to Python imports
- Show useful short test summary output

### `app/`

The main Python package for the application.

Because `app` is a package, Python can import files like:

```python
from app.main import create_app
from app.services.scans import ScanService
```

### `app/__init__.py`

Marks `app` as a Python package and stores:

```python
__version__ = "0.1.0"
```

Beginner note: `__init__.py` files often look small, but they tell Python that a
folder should be treated like an importable package.

### `app/main.py`

This is the application entry point.

It contains:

```python
def create_app() -> FastAPI:
    ...

app = create_app()
```

Why this matters:

- Uvicorn needs an ASGI app object.
- `app.main:app` means "inside `app/main.py`, load the variable named `app`."
- `create_app()` keeps app construction organized and testable.

Main responsibilities:

- Load settings
- Create `FastAPI(...)`
- Register global exception handlers
- Include routes under `/api/v1`

### `app/api/`

The HTTP API layer.

This folder exists because route handling is different from business logic.

The API layer should know about:

- HTTP paths
- HTTP methods
- Status codes
- FastAPI dependencies
- Request and response models

It should not contain heavy scanner logic.

### `app/api/__init__.py`

Marks `app/api` as a package and re-exports `get_scan_service`.

This makes selected API utilities easier to import.

### `app/api/dependencies.py`

Contains FastAPI dependency providers.

Current dependency:

```python
async def get_scan_service() -> ScanService:
    return ScanService()
```

Dependency injection means the route asks FastAPI for something it needs instead
of creating it manually.

Route example:

```python
scan_service: ScanService = Depends(get_scan_service)
```

Why this is useful:

- Tests can replace the real service with a fake service.
- Future database sessions can be injected.
- Routes stay clean.
- Service construction is centralized.

### `app/api/routes/`

Contains route modules.

A route module defines API endpoints.

This project has route modules such as:

```txt
app/api/routes/scans.py
app/api/routes/auth.py
app/api/routes/scrape.py
```

If the project grows, you might later add:

```txt
app/api/routes/users.py
app/api/routes/reports.py
```

### `app/api/routes/__init__.py`

Imports the scan router and exposes it as `scans_router`.

This allows `main.py` to import:

```python
from app.api.routes import scans_router
```

instead of importing directly from the deeper file.

### `app/api/routes/scans.py`

Defines the current API endpoints.

Important object:

```python
router = APIRouter(tags=["scans"])
```

`APIRouter` groups related routes together.

Routes in this file:

```python
@router.get("/health")
async def get_health() -> HealthResponse:
    ...
```

```python
@router.post("/scans")
async def create_scan(...) -> ScanResponse:
    ...
```

```python
@router.get("/scans")
async def list_scans(...) -> list[ScanResponse]:
    ...
```

```python
@router.get("/scans/{scan_id}")
async def get_scan(...) -> ScanResponse:
    ...
```

This file should mostly translate HTTP into service calls.

Example:

```python
return scan_service.create_scan(target_url=str(scan_request.target_url))
```

That line means:

1. Take the validated URL from the request.
2. Convert it to a string.
3. Pass it into the service layer.
4. Return the service result.

### `app/core/`

Contains app-wide infrastructure.

Core is for code that the whole app depends on, but that is not a route, schema,
or scanner service.

Current core files:

- `config.py`
- `exceptions.py`
- `security.py`

Future core files could include:

- `logging.py`
- `middleware.py`

### `app/core/__init__.py`

Marks `app/core` as a package and re-exports important core objects.

### `app/core/config.py`

Contains settings.

Current settings:

```python
class Settings(BaseModel):
    app_name: str = "Security Misconfiguration Scanner API"
    api_version: str = "0.1.0"
    debug: bool = False
    environment: str = "development"
```

`get_settings()` uses `@lru_cache`.

That means settings are created once and reused.

Beginner explanation:

Without caching, every call could create a new settings object. With caching,
Python remembers the first result and returns it again.

### `app/core/exceptions.py`

Contains global exception handling.

This file is important for security and consistency.

It handles:

- Validation errors
- Missing scans
- Invalid scan targets
- Unexpected exceptions

The global unexpected exception handler is:

```python
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception(
        "Unhandled exception while processing %s %s",
        request.method,
        request.url.path,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(
            error="internal_server_error",
            detail="An unexpected server error occurred.",
        ).model_dump(),
    )
```

This does two things:

1. Logs the real exception and traceback on the server.
2. Returns a safe generic error to the client.

This prevents stack trace leakage.

### `app/core/security.py`

Contains app-wide security helpers.

Current responsibilities:

- Hash plaintext passwords with bcrypt.
- Verify submitted passwords against stored password hashes.
- Create JWT access tokens.
- Decode JWT access tokens.

This belongs in `core` because password hashing and token handling are shared
security infrastructure. They are not only one route's job.

### `app/db/`

Contains database setup code.

This folder exists so database connection logic has one clear place.

It should know about:

- The database URL from settings
- The SQLAlchemy engine
- Session creation
- The shared SQLAlchemy base class

It should not contain HTTP route logic or request/response schemas.

### `app/db/base.py`

Defines the shared SQLAlchemy base class:

```python
class Base(DeclarativeBase):
    pass
```

Every SQLAlchemy model should inherit from this base.

Beginner explanation:

`Base` is like the common parent for database table classes. SQLAlchemy uses it
to understand which Python classes belong to your database model layer.

### `app/db/session.py`

Creates the database engine and session factory.

Important objects:

- `engine`: the connection point to the database
- `SessionLocal`: creates database sessions
- `get_db()`: FastAPI dependency that gives a route a database session

The `get_db()` function opens a session for the request and closes it after the
request finishes.

### `app/models/`

Contains SQLAlchemy ORM models.

Models describe database tables.

For example, `app/models/user.py` defines the `users` table:

```python
class User(Base):
    __tablename__ = "users"
```

A model answers questions like:

- What table exists in the database?
- What columns does the table have?
- Which columns are unique or required?
- What Python type should each database field use?

Why models are useful:

- They keep database structure separate from route code.
- They let Python code work with database rows as objects.
- They give migrations and queries a clear source of table definitions.

### `app/models/__init__.py`

Marks `app/models` as a package.

It can also be used to re-export models when the project grows.

### `app/models/user.py`

Defines the `User` database model.

Current columns:

- `id`
- `email`
- `hashed_password`
- `is_active`
- `created_at`

Important security detail:

The database stores `hashed_password`, not the original plaintext password.

### `app/repositories/`

Contains database access functions.

Repositories are a small layer between the rest of the app and raw database
queries.

They answer questions like:

- How do we find a user by email?
- How do we create a user?
- How do we check login credentials?

Why repositories are useful:

- Routes do not need to know SQLAlchemy query details.
- Database queries are easier to find and test.
- Duplicate database logic can be avoided.
- Future changes to database queries are kept in one place.

### `app/repositories/users.py`

Contains user-related database functions.

Current functions:

- `get_user_by_id(...)`
- `get_user_by_email(...)`
- `create_user(...)`
- `authenticate_user(...)`

It also defines `DuplicateEmailError`, which is raised when someone tries to
register with an email that already exists.

### `app/schemas/`

Contains Pydantic models.

Pydantic models define data shapes.

They answer questions like:

- What fields can the request contain?
- What type should each field be?
- What fields does the response contain?
- Should extra fields be rejected?

Important difference between `schemas` and `models`:

- `schemas` describe API input and output.
- `models` describe database tables.

Example:

- `UserCreate` in `app/schemas/auth.py` accepts a plaintext password from a
  request.
- `User` in `app/models/user.py` stores only `hashed_password` in the database.

Keeping them separate prevents accidentally returning private database fields
to API clients.

### `app/schemas/__init__.py`

Marks schemas as a package and re-exports schema classes.

### `app/schemas/errors.py`

Defines standard error response models.

`FieldValidationError` describes one field-level validation problem.

`ErrorResponse` describes the general error shape:

```json
{
  "error": "validation_error",
  "detail": []
}
```

Having one error shape helps frontend code because the frontend always knows
where to look for error information.

### `app/schemas/scans.py`

Defines scan-related schemas.

Important request schema:

```python
class ScanCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_url: HttpUrl = Field(...)
    include_exposed_files: bool = Field(default=True)
```

Meaning:

- `target_url` must be a valid HTTP or HTTPS URL.
- `include_exposed_files` defaults to `True`.
- Extra fields are rejected.

Important response schema:

```python
class ScanResponse(BaseModel):
    id: str
    target_url: str
    status: Literal["queued", "running", "completed", "failed"]
    created_at: datetime
    completed_at: datetime | None = None
    findings_count: int = 0
    findings: list[FindingResponse] = Field(default_factory=list)
    total_score: int | None = None
```

Beginner note:

Use `Field(default_factory=list)` for lists instead of `[]`. This avoids sharing
one mutable list across model instances.

### `app/services/`

Contains business logic.

Business logic means the rules of what the app actually does.

For this app, service logic means:

- Create scan results
- List scans
- Get scan by ID
- Later, run real scanner checks

### `app/services/__init__.py`

Marks services as a package and re-exports service classes and exceptions.

### `app/services/exceptions.py`

Defines service-level exceptions.

Current exceptions:

```python
class ScanServiceError(Exception):
    ...

class InvalidScanTargetError(ScanServiceError):
    ...

class ScanNotFoundError(ScanServiceError):
    ...

class ScannerExecutionError(RuntimeError):
    ...
```

Why custom exceptions are useful:

- They describe what went wrong.
- They avoid vague generic errors.
- Global handlers can map them to HTTP responses.

Example:

```txt
ScanNotFoundError -> 404 not_found
InvalidScanTargetError -> 400 bad_request
```

### `app/services/scans.py`

Contains `ScanService`.

Current method:

```python
def create_scan(self, target_url: str) -> ScanResponse:
    ...
```

Current behavior:

1. Strip whitespace from the URL.
2. Reject an empty URL.
3. Create mock findings.
4. Return a completed scan response.

Current findings are fake:

- Missing `Content-Security-Policy`
- Missing `X-Frame-Options`

Later, this file can be replaced with real scanner logic.

### `tests/`

Contains automated tests.

Tests are executable proof that the app works.

### `tests/api/`

Contains API tests.

These tests call the FastAPI app directly using HTTPX.

They do not need to start a real server.

### `tests/api/test_scans.py`

Tests successful behavior:

- Health endpoint works.
- Valid scan creation works.
- List scans returns an empty list.

### `tests/api/test_scan_errors.py`

Tests error behavior:

- Invalid URL returns `422`.
- Unsupported URL scheme returns `422`.
- Missing scan returns `404`.
- Business error returns `400`.
- Unexpected crash returns safe `500`.
- Unexpected crash is logged on the server.
- Stack trace does not leak into the HTTP response.

## 6. FastAPI Concepts Used Here

### `FastAPI`

`FastAPI` creates the application.

```python
app = FastAPI(title=settings.app_name)
```

The app receives ASGI requests and sends ASGI responses.

### `APIRouter`

`APIRouter` groups endpoints.

```python
router = APIRouter(tags=["scans"])
```

Then `main.py` mounts the router:

```python
app.include_router(scans_router, prefix="/api/v1")
```

This means a route declared as `/scans` becomes `/api/v1/scans`.

### Path Operation Decorators

FastAPI routes use decorators:

```python
@router.post("/scans")
```

This tells FastAPI:

- HTTP method: `POST`
- Path: `/scans`
- Function below handles that request

### `response_model`

Example:

```python
response_model=ScanResponse
```

This tells FastAPI to serialize and document the response using `ScanResponse`.

Benefits:

- Cleaner OpenAPI docs
- Predictable output
- Extra response fields can be filtered

### `status_code`

Example:

```python
status_code=status.HTTP_201_CREATED
```

This makes the create endpoint return `201 Created`.

### `Depends`

Example:

```python
scan_service: ScanService = Depends(get_scan_service)
```

This tells FastAPI:

"Before calling the route function, call `get_scan_service()` and give the result
to the `scan_service` parameter."

This is dependency injection.

## 7. Pydantic Concepts Used Here

### `BaseModel`

Pydantic models inherit from `BaseModel`.

```python
class ScanCreateRequest(BaseModel):
    target_url: HttpUrl
```

Pydantic reads input data and validates it.

### `Field`

`Field` adds metadata and validation options.

```python
target_url: HttpUrl = Field(
    ...,
    description="HTTP or HTTPS URL that will be scanned.",
)
```

The `...` means the field is required.

### `HttpUrl`

`HttpUrl` validates URLs.

It accepts:

```txt
https://example.com
http://example.com
```

It rejects:

```txt
not-a-url
ftp://example.com
```

### `ConfigDict(extra="forbid")`

This rejects unknown fields.

If the request model only allows:

```json
{
  "target_url": "https://example.com"
}
```

Then this will fail:

```json
{
  "target_url": "https://example.com",
  "extra": true
}
```

This is useful for APIs because clients cannot silently send unsupported fields.

### `Literal`

`Literal` restricts a field to specific values.

```python
status: Literal["queued", "running", "completed", "failed"]
```

This means status cannot be any random string.

## 8. Exception Handling Concepts

The app has expected errors and unexpected errors.

Expected errors:

- Invalid request body
- Missing scan
- Business rule rejection

Unexpected errors:

- Programming bug
- Database crash
- External scanner crash
- Runtime error

Expected errors can show useful details.

Unexpected errors should not show internal details to the client.

### Validation Error Flow

If the user sends:

```json
{
  "target_url": "not-a-url"
}
```

Pydantic/FastAPI raises `RequestValidationError`.

The app returns:

```json
{
  "error": "validation_error",
  "detail": [
    {
      "field": "target_url",
      "message": "...",
      "type": "..."
    }
  ]
}
```

### Not Found Flow

If the service raises:

```python
raise ScanNotFoundError("Scan 'abc' was not found.")
```

The app returns:

```json
{
  "error": "not_found",
  "detail": "Scan 'abc' was not found."
}
```

### Business Error Flow

If the service raises:

```python
raise InvalidScanTargetError("This target is not allowed.")
```

The app returns:

```json
{
  "error": "bad_request",
  "detail": "This target is not allowed."
}
```

### Unexpected Error Flow

If something raises:

```python
raise RuntimeError("database password leaked here")
```

The client should not see that message.

The client sees:

```json
{
  "error": "internal_server_error",
  "detail": "An unexpected server error occurred."
}
```

The server logs contain the real traceback.

## 9. Server Logging

The global 500 handler logs unexpected exceptions:

```python
logger.exception(
    "Unhandled exception while processing %s %s",
    request.method,
    request.url.path,
)
```

`logger.exception(...)` should be called inside an exception handler. It logs:

- Your message
- The exception type
- The exception message
- The stack trace

This is the correct security pattern:

```txt
Client response:
  safe and generic

Server logs:
  detailed traceback for developers/operators
```

Do not return stack traces to clients in production.

## 10. Testing Concepts

Tests use pytest.

Run tests:

```bash
.venv/bin/python -m pytest -q
```

The tests use HTTPX with ASGI transport:

```python
transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
```

This lets tests call the app directly without opening a network port.

Why `raise_app_exceptions=False` matters:

- If the app crashes, HTTPX returns the actual HTTP `500` response.
- The test can inspect the response body.
- This is needed to test that stack traces do not leak.

### Dependency Overrides In Tests

Tests can replace real dependencies:

```python
app.dependency_overrides[get_scan_service] = get_crashing_scan_service
```

This lets the test force an error without changing production code.

Example:

```python
class CrashingScanService(FakeScanService):
    def create_scan(self, target_url: str) -> ScanResponse:
        raise RuntimeError("database password leaked here")
```

Then the test verifies:

- HTTP status is `500`
- Client response is safe
- Server logs contain the traceback

## 11. How To Run The App

Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Run the development server:

```bash
uvicorn app.main:app --reload
```

Open docs:

```txt
http://127.0.0.1:8000/docs
```

Create a scan:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://example.com", "include_exposed_files": true}'
```

## 12. How To Read The Code As A Beginner

Start here:

1. `app/main.py`
2. `app/api/routes/scans.py`
3. `app/schemas/scans.py`
4. `app/services/scans.py`
5. `app/core/exceptions.py`
6. `tests/api/test_scans.py`
7. `tests/api/test_scan_errors.py`

Do not start with every file at once.

Recommended reading path:

### Step 1: Read app startup

Open `app/main.py`.

Understand:

- How the app is created
- How routes are included
- How exception handlers are registered

### Step 2: Read route definitions

Open `app/api/routes/scans.py`.

Understand:

- Which endpoints exist
- What schemas each route uses
- How routes call the service

### Step 3: Read schemas

Open `app/schemas/scans.py`.

Understand:

- What request fields are accepted
- What response fields are returned
- Which fields are required

### Step 4: Read service logic

Open `app/services/scans.py`.

Understand:

- Where mock findings come from
- How scan IDs are generated
- Which exceptions can be raised

### Step 5: Read exception handling

Open `app/core/exceptions.py`.

Understand:

- How validation errors become `422`
- How service errors become `400` or `404`
- How unexpected errors become safe `500`
- How server logging works

### Step 6: Read tests

Open `tests/api/test_scans.py` and `tests/api/test_scan_errors.py`.

Understand:

- What behavior is expected
- How fake services are used
- How errors are tested

## 13. Future Improvements To Practice

Beginner-friendly improvements:

1. Pass `include_exposed_files` from the route into the service.
2. Add a test proving `include_exposed_files=False` changes behavior.
3. Add a real in-memory scan history list.
4. Make `GET /api/v1/scans` return created scans.
5. Make `GET /api/v1/scans/{scan_id}` find a real scan.
6. Add a scanner check for `Strict-Transport-Security`.
7. Add a scanner check for `X-Content-Type-Options`.
8. Add structured log fields such as scan ID and request path.
9. Add a database later.
10. Add authentication later.

## 14. Key Security Lessons

This app teaches several secure API design basics:

- Validate input before using it.
- Reject unknown fields.
- Use consistent error responses.
- Do not leak stack traces to clients.
- Log unexpected errors on the server.
- Keep business logic out of routes.
- Use tests to prove security behavior.
- Be careful before building real URL scanning because scanners can introduce
  SSRF risk.

## 15. Terms To Remember

| Term | Meaning |
| --- | --- |
| API | A program interface clients call over HTTP |
| Route | A function connected to an HTTP method and path |
| Schema | A model describing request or response data |
| Service | Business logic layer |
| Dependency Injection | FastAPI creates/provides objects a route needs |
| Validation | Checking input before using it |
| Exception Handler | Code that converts errors into responses |
| Stack Trace | Detailed path of function calls before an error |
| Server Logs | Private operational logs for developers/operators |
| ASGI | Python web server interface used by FastAPI |
| Uvicorn | ASGI server used to run FastAPI |
| Pytest | Python test framework |
| HTTPX | HTTP client used in tests |

## 16. One-Screen Mental Model

Keep this picture in your head:

```txt
main.py builds the app
  |
  v
routes/scans.py receives HTTP
  |
  v
schemas/scans.py validates request data
  |
  v
dependencies.py provides ScanService
  |
  v
services/scans.py creates scan response
  |
  v
schemas/scans.py shapes response data
  |
  v
client receives JSON

If error:
  core/exceptions.py converts it to safe JSON
  and logs unexpected crashes on server
```

That is the whole app in one flow.
