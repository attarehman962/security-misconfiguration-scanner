# Security Misconfiguration Scanner API

A FastAPI-based API for running security misconfiguration scans against target
URLs. The current implementation exposes versioned scan routes, health checks,
mock scan responses, empty scan history, and structured error responses.

## Features

- FastAPI application factory in `app/main.py`
- Versioned API routes under `/api/v1`
- Dependency-injected scan service
- Pydantic request and response schemas
- Centralized exception handling
- Pytest coverage for scan routes and error responses

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

## Setup

From this `app/` directory, create and activate a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Run The API

Start the development server from this directory:

```bash
fastapi dev app/main.py
```

Or run with Uvicorn:

```bash
uvicorn app.main:app --reload
```

The API will be available at:

```txt
http://127.0.0.1:8000
```

Interactive API documentation:

```txt
http://127.0.0.1:8000/docs
```

## API Endpoints

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/api/v1/health` | Returns API status and a UTC timestamp. |
| `POST` | `/api/v1/scans` | Accepts a target URL and returns a mock security scan result. |
| `GET` | `/api/v1/scans` | Returns scan history. Currently returns an empty list. |
| `GET` | `/api/v1/scans/{scan_id}` | Returns a scan by ID or a consistent `404` response. |

### Example Scan Request

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://example.com"}'
```

### Example Validation Error

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target_url": "not-a-valid-url"}'
```

The API returns a `422` response with a stable error code and field-level
validation details.

## Run Tests

From this directory:

```bash
pytest
```

Expected result:

```txt
8 passed
```

## Notes

The scan endpoint currently returns mock data from `app/services/scans.py`.
Future work can replace this service with real scanner integrations and
persistent scan storage.
