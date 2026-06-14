# Security Misconfiguration Scanner API

A FastAPI-based API for running security misconfiguration scans against target
URLs. The current implementation exposes health checks, a mock scan response,
empty scan history, and structured validation errors.

## Features

- FastAPI application factory in `app/main.py`
- Health check endpoint with UTC timestamp
- URL scan endpoint with Pydantic request validation
- Custom validation error response format
- Modular routers, schemas, services, and configuration
- Placeholder auth and scraping routers for upcoming features
- Pytest coverage for health and scan routes

## Project Structure

```txt
README.md
requirements.txt
pytest.ini
app/
  __init__.py
  main.py
  core/
    __init__.py
    config.py
  routers/
    __init__.py
    auth.py
    scan.py
    scrape.py
  schemas/
    __init__.py
    auth.py
    error.py
    scan.py
  services/
    __init__.py
    scanner_service.py
    scraping_service.py
tests/
  test_health.py
  test_scan_routes.py
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
| `GET` | `/health` | Returns API status and a UTC timestamp. |
| `POST` | `/scan` | Accepts a target URL and returns a mock security scan result. |
| `GET` | `/scans` | Returns scan history. Currently returns an empty list. |

### Example Scan Request

```bash
curl -X POST http://127.0.0.1:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

### Example Validation Error

```bash
curl -X POST http://127.0.0.1:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "not-a-valid-url"}'
```

The API returns a custom `422` response with a top-level message and field-level
validation errors.

## Run Tests

From this directory:

```bash
pytest
```

Expected result:

```txt
5 passed
```

## Notes

The scan endpoint currently returns mock data from
`app/services/scanner_service.py`. Future work can replace this service with
real scanner integrations and persistent scan storage.
