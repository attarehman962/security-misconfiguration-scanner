# Security Misconfiguration Scanner API

A FastAPI API for creating and reading security misconfiguration scan results.
The current project is a clean API skeleton: it validates scan requests, returns
mock scan findings, exposes versioned routes, and uses centralized exception
handlers so every error response has a stable JSON shape.

This README explains how the code is structured, how a request flows through the
application, how exceptions are handled, how to run and test the project, and
how to think about future deployment.

## Current Status

This project currently provides:

- A FastAPI application factory in `app/main.py`
- Versioned API routes under `/api/v1`
- A scan creation endpoint: `POST /api/v1/scans`
- A health endpoint: `GET /api/v1/health`
- A scan history endpoint: `GET /api/v1/scans`
- A single scan lookup endpoint: `GET /api/v1/scans/{scan_id}`
- Pydantic request and response models
- Dependency injection for the scan service
- Centralized error handling in `app/core/exceptions.py`
- Tests for successful API flow and error response flow

Important current limitations:

- Scan results are mocked in `app/services/scans.py`.
- There is no database or persistent scan history yet.
- `GET /api/v1/scans` currently returns an empty list.
- `GET /api/v1/scans/{scan_id}` currently always raises `ScanNotFoundError`.
- The scanner does not yet perform real HTTP/header/file/security checks.
- The create scan request currently accepts `target_url` and
  `include_exposed_files`, but `include_exposed_files` is not wired into service
  behavior yet.

## Technology Stack

- Python
- FastAPI for the HTTP API
- Starlette underneath FastAPI for ASGI routing and exception handling
- Pydantic for request validation and response schemas
- Uvicorn or FastAPI CLI for running the app locally
- HTTPX for ASGI-based API tests
- Pytest for test execution

Dependencies are listed in `requirements.txt`.

## Project Structure

```txt
README.md
requirements.txt
pytest.ini
app/
  __init__.py
  main.py
  api/
    __init__.py
    dependencies.py
    routes/
      __init__.py
      scans.py
  core/
    __init__.py
    config.py
    exceptions.py
  schemas/
    __init__.py
    errors.py
    scans.py
  services/
    __init__.py
    exceptions.py
    scans.py
tests/
  api/
    __init__.py
    test_scan_errors.py
    test_scans.py
```

## Why The Project Is Split This Way

The code is separated by responsibility so each file has one clear reason to
exist.

The high-level idea is:

```txt
main.py
  creates the app
api/
  receives HTTP requests
schemas/
  validates input and shapes output
services/
  contains business logic
core/
  contains app-wide configuration and behavior
tests/
  proves the public API behavior
```

This keeps route functions small. A route should mostly translate HTTP input
into a service call. The service should know how scan behavior works. Schemas
should describe the data contract. Core should hold things the whole app needs,
such as settings and exception registration.

## Folder And File Purpose

`README.md`

Human documentation for the project. It explains how to run the API, how the
code is organized, how requests move through the app, how errors are handled,
and how the project can grow toward a real scanner.

`requirements.txt`

The Python dependency list. It tells pip what packages the project needs:
FastAPI, Starlette, Pydantic, Pytest, and HTTPX. Without this file, a new
environment would not know which libraries to install.

`pytest.ini`

Pytest configuration. It tells pytest to:

- Look for tests under `tests`
- Add the project root to `pythonpath`
- Show extra summary information for skipped, failed, and errored tests

`app/`

The main application package. Code inside this folder is importable as
`app.something`. Keeping source code inside a package makes imports predictable
and keeps application code separate from tests and project metadata.

`app/__init__.py`

Marks `app` as a Python package and stores the package version:

```python
__version__ = "0.1.0"
```

This file is small, but important. It lets Python import modules such as
`security_scanner.main`, `security_scanner.api.v1.routes.scans`, and `security_scanner.services.scans`.

`app/main.py`

The application entry point. It contains `create_app()`, which builds and
configures the FastAPI app.

Why this file exists:

- Creates the `FastAPI` instance
- Reads settings from `app/core/config.py`
- Registers global exception handlers from `app/core/exceptions.py`
- Mounts the scan router under `/api/v1`
- Exposes the final ASGI variable named `app`

ASGI servers such as Uvicorn load this object:

```bash
uvicorn security_scanner.main:app --reload
```

`app/api/`

The HTTP API layer. This folder contains code that is close to FastAPI route
handling: routes, dependencies, request wiring, and response declarations.

Why `api` exists:

- Keeps HTTP concerns out of business logic
- Groups route modules in one predictable place
- Makes future API versioning easier
- Gives dependency providers a home near the routes that use them

`app/api/__init__.py`

Marks `app/api` as a package and re-exports `get_scan_service`.

Why this file exists:

- Keeps import paths clean
- Makes API-layer utilities available from `security_scanner.api.v1`
- Documents that this folder owns route/dependency concerns

`app/api/dependencies.py`

Contains FastAPI dependency provider functions.

Current dependency:

```python
async def get_scan_service() -> ScanService:
    return ScanService()
```

Why dependencies are separated:

- Routes do not need to know how services are constructed
- Tests can override dependencies with fake services
- Future database sessions, auth users, settings, or clients can be injected
  from one place
- The route signature stays explicit and easy to read

In tests, this design allows:

```python
app.dependency_overrides[get_scan_service] = get_fake_scan_service
```

`app/api/routes/`

Contains route modules. A route module defines actual HTTP endpoints such as
`GET /health` or `POST /scans`.

Why `routes` exists:

- Keeps endpoint declarations separate from dependency setup
- Lets the project grow by adding files like `users.py`, `auth.py`, or
  `reports.py`
- Keeps `main.py` small because it only includes routers

`app/api/routes/__init__.py`

Imports and re-exports the scan router:

```python
from security_scanner.api.v1.routes.scans import router as scans_router
```

Why this file exists:

- Gives `main.py` a simple import path
- Hides the internal router module name
- Makes it easy to add more routers later

`app/api/routes/scans.py`

Defines all current API endpoints:

- `GET /health`
- `POST /scans`
- `GET /scans`
- `GET /scans/{scan_id}`

Why this file exists:

- Receives HTTP requests
- Declares response models and status codes
- Uses Pydantic request schemas
- Uses `Depends(get_scan_service)` to access the service layer
- Converts validated request data into service calls
- Returns service responses back to FastAPI

This file should stay thin. If route logic starts becoming complicated, that
logic usually belongs in `app/services/scans.py`.

`app/core/`

Application-wide core infrastructure. This folder is for code that is not a
route, not a schema, and not scan business logic, but is needed by the whole
application.

Why `core` exists:

- Keeps global app setup separate from endpoint code
- Gives shared configuration a home
- Gives exception registration a home
- Prevents `main.py` from becoming crowded

Good future candidates for `core`:

- Logging configuration
- CORS setup
- Security settings
- App lifespan setup
- Global middleware setup

`app/core/__init__.py`

Marks `app/core` as a package and re-exports:

- `Settings`
- `get_settings`
- `register_exception_handlers`

Why this file exists:

- Makes core utilities easy to import
- Documents which core objects are public for the rest of the app

`app/core/config.py`

Contains application settings.

Current settings:

- `app_name`
- `api_version`
- `debug`
- `environment`

Why this file exists:

- Centralizes app configuration
- Avoids hardcoding settings throughout route files
- Uses `@lru_cache` so settings are created once and reused
- Gives a clear place to add environment-based settings later

`app/core/exceptions.py`

Contains global exception handlers and the function that registers them with
FastAPI.

Why this file exists:

- Keeps error formatting consistent across all routes
- Converts Pydantic/FastAPI validation errors into this API's error shape
- Converts service exceptions into HTTP responses
- Sanitizes unexpected exceptions so raw internals are not leaked
- Keeps exception registration out of `main.py`

Current handlers:

- `RequestValidationError` -> `422 validation_error`
- `ScanNotFoundError` -> `404 not_found`
- `InvalidScanTargetError` -> `400 bad_request`
- `Exception` -> `500 internal_server_error`

`app/schemas/`

Pydantic data models. These models define the API contract: what input is
accepted and what output is returned.

Why `schemas` exists:

- Keeps data shape definitions separate from routes and services
- Gives FastAPI enough information to generate OpenAPI docs
- Validates request bodies before they reach business logic
- Ensures responses have a predictable structure

`app/schemas/__init__.py`

Marks `app/schemas` as a package and re-exports schema classes.

Why this file exists:

- Makes schema imports cleaner
- Defines the public schema names for the rest of the project

`app/schemas/errors.py`

Contains standard error response models:

- `FieldValidationError`
- `ErrorResponse`

Why this file exists:

- Gives every error a stable JSON shape
- Lets exception handlers build responses through Pydantic
- Keeps error response contracts separate from scan response contracts

`app/schemas/scans.py`

Contains scan-related request and response models:

- `ScanCreateRequest`
- `FindingResponse`
- `ScanResponse`
- `HealthResponse`

Why this file exists:

- Validates `POST /api/v1/scans` request bodies
- Describes scan finding objects
- Describes full scan responses
- Describes health check responses
- Keeps OpenAPI docs accurate

`app/services/`

Business logic layer. This folder is where scanner behavior belongs.

Why `services` exists:

- Keeps business rules out of route functions
- Makes scanner behavior testable without HTTP
- Gives a clear place to add real scanning, persistence, queues, and scoring
- Lets the API layer stay focused on HTTP

`app/services/scans.py`

Contains `ScanService`.

Current methods:

- `create_scan(...)`
- `list_scans()`
- `get_scan_by_id(...)`

Why this file exists:

- Owns scan creation behavior
- Owns scan lookup behavior
- Creates mock findings for now
- Will be the natural place to integrate real scanner checks later
- Raises service-layer exceptions when business rules fail

`app/services/exceptions.py`

Contains exceptions raised by the service layer:

- `ScanServiceError`
- `InvalidScanTargetError`
- `ScanNotFoundError`
- `ScannerExecutionError`

Why this file exists:

- Gives business failures meaningful names
- Avoids raising generic `Exception` for expected service problems
- Lets `app/core/exceptions.py` map domain errors to HTTP responses
- Keeps service errors separate from FastAPI-specific errors

`tests/`

Test suite root.

Why `tests` exists:

- Keeps tests outside production application code
- Gives pytest a predictable place to discover tests
- Documents expected behavior through executable examples

`tests/api/`

API-level tests. These tests call the FastAPI ASGI app directly using HTTPX.

Why `tests/api` exists:

- Groups tests by the surface they test: the HTTP API
- Keeps room for future folders such as `tests/services`
- Makes it clear these tests verify routes, validation, dependency overrides,
  and HTTP responses

`tests/api/__init__.py`

Marks the API tests folder as a Python package.

`tests/api/test_scans.py`

Tests successful API behavior:

- Health endpoint returns `200`
- Valid scan creation returns `201`
- List scans returns an empty list

`tests/api/test_scan_errors.py`

Tests error behavior:

- Invalid URL returns `422`
- Unsupported URL scheme returns `422`
- Missing scan returns `404`
- Business-rule rejection returns `400`
- Unexpected crash returns sanitized `500`

These tests use dependency overrides to force specific service behavior without
needing a real scanner or database.

## Application Startup Flow

The app starts from `app/main.py`.

```python
app = create_app()
```

Startup flow:

1. `create_app()` is called.
2. `get_settings()` returns the cached settings object.
3. `FastAPI(...)` creates the ASGI app with title, version, and debug config.
4. `register_exception_handlers(app)` adds global exception handlers.
5. `app.include_router(scans_router, prefix="/api/v1")` mounts scan routes.
6. The configured `app` object is served by FastAPI CLI, Uvicorn, or another
   ASGI server.

The route prefix means a route declared as `/scans` becomes:

```txt
/api/v1/scans
```

## User Flow

Typical user flow:

1. A user or frontend opens the API docs at `/docs`.
2. The user sends a scan request to `POST /api/v1/scans`.
3. The request body includes a `target_url` and can include
   `include_exposed_files`.
4. FastAPI and Pydantic validate the JSON body.
5. The route handler receives a `ScanCreateRequest`.
6. The route handler calls `ScanService.create_scan(...)`.
7. The service returns a `ScanResponse`.
8. FastAPI serializes the response to JSON.
9. The client receives a `201 Created` response.

## Create Scan Request Flow

The create scan route is defined in `app/api/routes/scans.py`.

```python
@router.post(
    "/scans",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a security scan",
)
async def create_scan(
    scan_request: ScanCreateRequest,
    scan_service: ScanService = Depends(get_scan_service),
) -> ScanResponse:
    return scan_service.create_scan(target_url=str(scan_request.target_url))
```

Request flow in detail:

1. Client sends:

   ```http
   POST /api/v1/scans
   Content-Type: application/json
   ```

2. Client body:

   ```json
   {
     "target_url": "https://example.com",
     "include_exposed_files": true
   }
   ```

3. FastAPI matches the request to the `POST /scans` route inside the router.
4. The router is mounted with prefix `/api/v1`, so the full endpoint is
   `/api/v1/scans`.
5. FastAPI sees the parameter `scan_request: ScanCreateRequest`.
6. Pydantic validates the request body against `ScanCreateRequest`.
7. `target_url` must be a valid HTTP or HTTPS URL because it uses `HttpUrl`.
8. `include_exposed_files` must be a boolean if provided.
9. Extra JSON fields are rejected because the model uses
   `ConfigDict(extra="forbid")`.
10. FastAPI resolves `scan_service` using `Depends(get_scan_service)`.
11. `get_scan_service()` returns a `ScanService`.
12. The route converts the Pydantic URL object to a string.
13. The route calls `scan_service.create_scan(...)`.
14. Current note: the route does not yet pass `include_exposed_files` into the
    service, so the flag is accepted by the schema but does not change scan
    behavior yet.
15. The service normalizes the string with `.strip()`.
16. The service returns a `ScanResponse` with mock findings.
17. FastAPI validates/serializes that response using `response_model`.
18. The client receives `201 Created`.

## Request Schema

The create scan request model is in `app/schemas/scans.py`.

```python
class ScanCreateRequest(BaseModel):
    """Request body used to start a new security scan."""

    model_config = ConfigDict(extra="forbid")

    target_url: HttpUrl = Field(
        ...,
        description="HTTP or HTTPS URL that will be scanned.",
        examples=["https://example.com"],
    )
    include_exposed_files: bool = Field(
        default=True,
        description="Whether to include exposed file checks in the scan.",
    )
```

Fields:

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `target_url` | `HttpUrl` | Yes | The HTTP or HTTPS URL to scan. |
| `include_exposed_files` | `bool` | No | Intended flag for whether exposed-file checks should run. Currently accepted by the request model but not used by `ScanService.create_scan(...)` yet. |

Because `extra="forbid"` is enabled, this body is rejected:

```json
{
  "target_url": "https://example.com",
  "unknown_field": true
}
```

`include_exposed_files` must stay as its own field on `ScanCreateRequest`. It
should not be placed inside the `Field(...)` call for `target_url`.

Correct pattern:

```python
class ScanCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_url: HttpUrl = Field(
        ...,
        description="HTTP or HTTPS URL that will be scanned.",
        examples=["https://example.com"],
    )
    include_exposed_files: bool = Field(
        default=True,
        description="Whether to include exposed file checks in the scan.",
    )
```

## Response Schema

Successful scan responses use `ScanResponse` from `app/schemas/scans.py`.

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

Finding objects use `FindingResponse`.

```python
class FindingResponse(BaseModel):
    check_name: str
    status: Literal["pass", "fail", "error"]
    severity: Literal["critical", "high", "medium", "low", "info"]
    description: str
    remediation: str | None = None
```

Example successful response:

```json
{
  "id": "scan_abc123",
  "target_url": "https://example.com/",
  "status": "completed",
  "created_at": "2026-06-15T04:00:00Z",
  "completed_at": "2026-06-15T04:00:00Z",
  "findings_count": 2,
  "findings": [
    {
      "check_name": "security_headers",
      "status": "fail",
      "severity": "medium",
      "description": "Missing Content-Security-Policy header.",
      "remediation": "Add a strict Content-Security-Policy header."
    },
    {
      "check_name": "x_frame_options",
      "status": "fail",
      "severity": "low",
      "description": "Missing X-Frame-Options header.",
      "remediation": "Add a strict X-Frame-Options header."
    }
  ],
  "total_score": 85
}
```

## Service Flow

The scan service is in `app/services/scans.py`.

Current `create_scan` behavior:

1. Receives `target_url` as a string.
2. Strips whitespace.
3. Rejects an empty value with `InvalidScanTargetError`.
4. Builds two mock findings:
   - Missing `Content-Security-Policy`
   - Missing `X-Frame-Options`
5. Creates a timestamp with `datetime.now(UTC)`.
6. Returns a `ScanResponse`.

Current mock result:

- ID format: `scan_<uuid hex>`
- Status: `completed`
- Findings count: `2`
- Total score: `85`

This layer is the right place to add real scanner logic later. For example:

- Fetch target URL headers.
- Check security headers.
- Check TLS configuration.
- Check exposed files such as `.env`, `.git/config`, `backup.zip`, or
  `phpinfo.php`.
- Store scan records in a database.
- Run long scans in a background task or queue.
- Return `queued` first, then allow clients to poll by scan ID.

## Dependency Injection Flow

The route does not create `ScanService` directly. It asks FastAPI to inject it:

```python
scan_service: ScanService = Depends(get_scan_service)
```

The dependency provider is:

```python
async def get_scan_service() -> ScanService:
    return ScanService()
```

Benefits:

- Routes stay thin.
- Service creation is centralized.
- Tests can override the dependency.
- Future database/session dependencies can be added in one place.

Tests use this pattern to replace the real service with fake services that
raise specific exceptions.

## API Endpoints

| Method | Endpoint | Status | Description |
| --- | --- | --- | --- |
| `GET` | `/api/v1/health` | `200` | Returns API status and current UTC timestamp. |
| `POST` | `/api/v1/scans` | `201` | Creates a mock security scan for a valid target URL. |
| `GET` | `/api/v1/scans` | `200` | Returns scan history. Currently returns `[]`. |
| `GET` | `/api/v1/scans/{scan_id}` | `200` or `404` | Looks up one scan. Currently always returns `404`. |

## How To Run Locally

From this repository directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Run with FastAPI CLI:

```bash
fastapi dev app/main.py
```

Run with Uvicorn:

```bash
uvicorn security_scanner.main:app --reload
```

The API should be available at:

```txt
http://127.0.0.1:8000
```

Interactive Swagger UI:

```txt
http://127.0.0.1:8000/docs
```

ReDoc documentation:

```txt
http://127.0.0.1:8000/redoc
```

OpenAPI JSON:

```txt
http://127.0.0.1:8000/openapi.json
```

## How To Use The API

Health check:

```bash
curl http://127.0.0.1:8000/api/v1/health
```

Create a scan:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://example.com"}'
```

Create a scan with the currently accepted exposed-file flag:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://example.com", "include_exposed_files": true}'
```

Current note: `include_exposed_files` is validated by the request schema, but
the route does not yet pass it to `ScanService.create_scan(...)`, so it does not
change the returned mock findings yet.

List scans:

```bash
curl http://127.0.0.1:8000/api/v1/scans
```

Get one scan:

```bash
curl http://127.0.0.1:8000/api/v1/scans/scan_test_123
```

Validation error example:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target_url": "not-a-valid-url"}'
```

Unsupported scheme example:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target_url": "ftp://example.com"}'
```

Extra field rejection example:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://example.com", "extra": true}'
```

## Error Response Shape

All API errors should use this general shape:

```json
{
  "error": "machine_readable_code",
  "detail": "human readable detail or structured details"
}
```

The error schema is in `app/schemas/errors.py`.

```python
class ErrorResponse(BaseModel):
    error: str
    detail: str | list[FieldValidationError] | dict[str, Any] | None = None
```

Validation errors use a list of field-level errors:

```json
{
  "error": "validation_error",
  "detail": [
    {
      "field": "target_url",
      "message": "Input should be a valid URL",
      "type": "url_parsing"
    }
  ]
}
```

The exact validation `message` and `type` can vary by Pydantic version, but the
project keeps the outer API shape stable.

## Exception Classes

Service exceptions live in `app/services/exceptions.py`.

| Exception | Parent | Meaning | Current Handler |
| --- | --- | --- | --- |
| `ScanServiceError` | `Exception` | Base class for scan service failures. | No direct handler yet. |
| `InvalidScanTargetError` | `ScanServiceError` | Target passed validation but violates scanner policy. | `400 bad_request` |
| `ScanNotFoundError` | `ScanServiceError` | Requested scan ID does not exist. | `404 not_found` |
| `ScannerExecutionError` | `RuntimeError` | Scanner failed while running. | Falls through to global `500` unless a specific handler is added. |

## Exception Handling Flow

Global exception handlers are registered in `app/core/exceptions.py`.

```python
def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(
        RequestValidationError,
        cast(ExceptionHandler, validation_exception_handler),
    )
    app.add_exception_handler(
        ScanNotFoundError,
        cast(ExceptionHandler, scan_not_found_exception_handler),
    )
    app.add_exception_handler(
        InvalidScanTargetError,
        cast(ExceptionHandler, invalid_scan_target_exception_handler),
    )
    app.add_exception_handler(
        Exception,
        cast(ExceptionHandler, unhandled_exception_handler),
    )
```

The `cast(ExceptionHandler, ...)` calls are for static type checkers such as
Pylance/Pyright. Runtime behavior is still FastAPI/Starlette normal exception
handler registration.

Exception flow:

1. A request enters FastAPI.
2. FastAPI validates route parameters and request body.
3. If validation fails, FastAPI raises `RequestValidationError`.
4. The registered validation handler returns `422`.
5. If validation succeeds, the route calls the service.
6. If the service raises `ScanNotFoundError`, the not-found handler returns
   `404`.
7. If the service raises `InvalidScanTargetError`, the bad-request handler
   returns `400`.
8. If any other unhandled exception is raised, the catch-all handler returns
   sanitized `500`.

## Error Cases By Endpoint

`POST /api/v1/scans`

| Situation | Example | Status | Error Code |
| --- | --- | --- | --- |
| Invalid URL | `not-a-url` | `422` | `validation_error` |
| Unsupported URL scheme | `ftp://example.com` | `422` | `validation_error` |
| Extra JSON field | `{"extra": true}` | `422` | `validation_error` |
| Business rejection | Service raises `InvalidScanTargetError` | `400` | `bad_request` |
| Unexpected crash | Service raises `RuntimeError` | `500` | `internal_server_error` |

`GET /api/v1/scans/{scan_id}`

| Situation | Example | Status | Error Code |
| --- | --- | --- | --- |
| Scan missing | Unknown scan ID | `404` | `not_found` |
| Unexpected crash | Service/database failure | `500` | `internal_server_error` |

## Why The Global 500 Handler Is Important

The catch-all handler prevents raw exception messages, tracebacks, local file
paths, secrets, and package details from leaking to clients.

Instead of returning something like:

```txt
RuntimeError: database password leaked here
```

the API returns:

```json
{
  "error": "internal_server_error",
  "detail": "An unexpected server error occurred."
}
```

The test `test_unhandled_exception_returns_clean_500_without_traceback` verifies
this behavior.

## Tests

Run tests from the project directory:

```bash
source .venv/bin/activate
pytest
```

or:

```bash
.venv/bin/python -m pytest -q
```

Expected result:

```txt
8 passed
```

Current test coverage includes:

- Health endpoint returns `200`.
- Valid create scan request returns `201`.
- List scans returns an empty list.
- Invalid URL returns `422`.
- Unsupported scheme returns `422`.
- Missing scan returns consistent `404`.
- Business rejection returns consistent `400`.
- Unexpected exception returns sanitized `500`.

The tests call the ASGI app directly with HTTPX:

```python
transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
```

`raise_app_exceptions=False` is important because it lets tests inspect the
actual HTTP `500` response instead of letting the exception escape into pytest.

## Development Workflow

Suggested workflow:

1. Activate the virtual environment.
2. Run tests before changing behavior.
3. Make a small code change.
4. Add or update tests for the changed behavior.
5. Run `pytest`.
6. Try the endpoint manually with `curl` or `/docs`.
7. Keep schemas, route responses, and README examples in sync.

Useful commands:

```bash
source .venv/bin/activate
pytest
uvicorn security_scanner.main:app --reload
```

Remove Python cache folders from project code:

```bash
find app tests -type d -name __pycache__ -prune -exec rm -r {} +
```

## Wiring A Scan Option Into Behavior

Example goal: make the existing `include_exposed_files` request field actually
control exposed-file checks.

Recommended steps:

1. Keep the field on `ScanCreateRequest` in `app/schemas/scans.py`.
2. Update the route in `app/api/routes/scans.py` to pass the option into the
   service.
3. Update `ScanService.create_scan(...)` to accept the option.
4. Use the option to include or skip exposed-file checks.
5. Add tests for default behavior and explicit `false`.
6. Update this README's request examples.

Current schema field:

```python
include_exposed_files: bool = Field(
    default=True,
    description="Whether to include exposed file checks in the scan.",
)
```

Example request:

```json
{
  "target_url": "https://example.com",
  "include_exposed_files": true
}
```

## Adding Real Scanner Logic

The current scanner is mocked. A real scanner can evolve in stages.

Stage 1: HTTP header checks

- Fetch the target URL.
- Read response headers.
- Check for `Content-Security-Policy`.
- Check for `X-Frame-Options` or CSP `frame-ancestors`.
- Check for `Strict-Transport-Security` on HTTPS.
- Check for `X-Content-Type-Options`.
- Check for `Referrer-Policy`.
- Convert each failed check into a `FindingResponse`.

Stage 2: Exposed file checks

- Build a safe allowlist of paths to check.
- Avoid aggressive crawling.
- Respect timeouts.
- Request paths such as `/.env`, `/.git/config`, `/backup.zip`,
  `/phpinfo.php`, and `/server-status`.
- Treat `200 OK` with sensitive-looking content as a finding.
- Avoid reporting false positives from custom `404` pages.

Stage 3: Persistence

- Add a database model for scans.
- Store scan status, timestamps, target URL, findings, and score.
- Make `GET /api/v1/scans` return real scan history.
- Make `GET /api/v1/scans/{scan_id}` return stored results.

Stage 4: Background execution

- Return `queued` immediately.
- Run scanning in a background worker.
- Let clients poll `GET /api/v1/scans/{scan_id}`.
- Add `running`, `completed`, and `failed` transitions.

Stage 5: Production controls

- Add authentication.
- Add rate limiting.
- Add target allow/deny rules.
- Block private/internal IP ranges unless intentionally allowed.
- Log scanner execution safely.
- Add request IDs for traceability.

## Security Notes

Scanner APIs can be risky because users submit URLs that the server then
requests. Before turning this into a real scanner, consider:

- Server-Side Request Forgery protection.
- Blocking private IP ranges by default.
- Blocking localhost targets by default.
- DNS rebinding protection.
- Request timeouts.
- Maximum response body sizes.
- Redirect limits.
- User authentication.
- Per-user rate limits.
- Audit logs.
- Explicit permission rules for scanning third-party domains.

The current code does not make outbound scan requests, so these risks are
future-work items rather than current runtime behavior.

## Configuration

Settings live in `app/core/config.py`.

Current settings:

| Setting | Default | Purpose |
| --- | --- | --- |
| `app_name` | `Security Misconfiguration Scanner API` | FastAPI app title. |
| `api_version` | `0.1.0` | FastAPI app version. |
| `debug` | `False` | FastAPI debug flag. |
| `environment` | `development` | Environment label. |

`get_settings()` is cached with `@lru_cache`, so the settings object is reused
instead of rebuilt repeatedly.

Current settings are hardcoded defaults. If environment-based configuration is
needed later, convert `Settings` to use Pydantic Settings from
`pydantic-settings`.

## Deployment Ways

This repo does not currently include production deployment files, but the app is
standard ASGI and can be deployed in several common ways.

### 1. Local Development

Use this while building and testing:

```bash
uvicorn security_scanner.main:app --reload
```

`--reload` watches files and restarts the server when code changes. Do not use
`--reload` in production.

### 2. Simple Production Uvicorn Process

For a small server or VM:

```bash
uvicorn security_scanner.main:app --host 0.0.0.0 --port 8000
```

Put a reverse proxy such as Nginx, Caddy, Traefik, or a cloud load balancer in
front of it for HTTPS and public traffic.

### 3. Multiple Workers

For CPU/process concurrency, run multiple worker processes:

```bash
uvicorn security_scanner.main:app --host 0.0.0.0 --port 8000 --workers 4
```

Choose the worker count based on CPU, memory, workload, and deployment platform.

### 4. Docker

Example `Dockerfile`:

```dockerfile
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

EXPOSE 8000

CMD ["uvicorn", "security_scanner.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

Build:

```bash
docker build -t security-misconfiguration-scanner-api .
```

Run:

```bash
docker run --rm -p 8000:8000 security-misconfiguration-scanner-api
```

### 5. Cloud Platform

Most platforms that support Python web apps or containers can run this project:

- Render
- Railway
- Fly.io
- DigitalOcean App Platform
- AWS ECS/App Runner/Elastic Beanstalk
- Google Cloud Run
- Azure Container Apps

Typical container command:

```bash
uvicorn security_scanner.main:app --host 0.0.0.0 --port ${PORT:-8000}
```

Some platforms provide a `PORT` environment variable. If the platform requires
that, make sure your start command uses it.

### 6. Reverse Proxy Setup

Common production shape:

```txt
Internet
  -> HTTPS load balancer or reverse proxy
  -> Uvicorn ASGI process
  -> FastAPI app
  -> service layer
  -> scanner/database/queue
```

Recommended production responsibilities:

- Reverse proxy handles HTTPS.
- App server handles ASGI requests.
- Background worker handles long scans.
- Database stores scan state.
- Logs/metrics system stores observability data.

## Production Readiness Checklist

Before using this as a real scanner service:

- Add authentication and authorization.
- Add scan ownership so users cannot read other users' scans.
- Add persistent storage.
- Add background jobs for long scans.
- Add SSRF protections.
- Add rate limiting.
- Add request timeouts.
- Add structured logging.
- Add CORS policy if used by a browser frontend.
- Add deployment health checks.
- Add CI test execution.
- Add type checking if you want editor errors caught in CI.
- Add real scanner tests with mocked HTTP responses.

## Study Sources

Primary documentation for the stack:

- FastAPI documentation: https://fastapi.tiangolo.com/
- FastAPI request bodies: https://fastapi.tiangolo.com/tutorial/body/
- FastAPI error handling: https://fastapi.tiangolo.com/tutorial/handling-errors/
- FastAPI deployment: https://fastapi.tiangolo.com/deployment/
- FastAPI Docker deployment: https://fastapi.tiangolo.com/deployment/docker/
- FastAPI Uvicorn workers: https://fastapi.tiangolo.com/deployment/server-workers/
- Pydantic models: https://docs.pydantic.dev/latest/concepts/models/
- Pytest documentation: https://docs.pytest.org/en/stable/
- Uvicorn deployment: https://www.uvicorn.org/deployment/

Security study sources:

- OWASP Web Security Testing Guide:
  https://owasp.org/www-project-web-security-testing-guide/
- OWASP Top 10:
  https://owasp.org/www-project-top-ten/

Topics to study for this project:

- FastAPI routing and dependency injection.
- Pydantic model validation.
- Starlette exception handlers.
- HTTP status codes.
- OpenAPI schemas.
- Pytest API testing.
- HTTPX ASGI testing.
- Web security headers.
- SSRF prevention.
- OWASP testing methodology.
- Docker deployment.
- Reverse proxy deployment.

## Quick Reference

Install:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Run:

```bash
uvicorn security_scanner.main:app --reload
```

Test:

```bash
pytest
```

Create scan:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://example.com"}'
```

Docs:

```txt
http://127.0.0.1:8000/docs
```

Main code path:

```txt
app/main.py
  -> app/core/exceptions.py
  -> app/api/routes/scans.py
  -> app/api/dependencies.py
  -> app/services/scans.py
  -> app/schemas/scans.py
```
