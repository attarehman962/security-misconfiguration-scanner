# Security Misconfiguration Scanner

A Python security scanner for learning, portfolio work, and authorized testing.
It can run from the command line or as a FastAPI service, checking a target URL
for common web security misconfigurations and returning structured results.

This is not a replacement for a professional penetration test. Only scan
systems you own or have explicit permission to test.

## Features

- CLI scanner with table or JSON output.
- FastAPI app with versioned routes under `/api/v1`.
- Background scan jobs with status lookup.
- Security header checks for HSTS, CSP, X-Frame-Options, and related headers.
- Exposure checks for weak CORS, server banners, `/.env`, `/.git/config`, and
  directory listing indicators.
- HTTPS/TLS expiry checks.
- JWT-based user registration, login, and current-user route.
- Protected scrape route scaffold.
- SQLAlchemy database setup with Alembic migrations.
- Pytest, Ruff, and mypy development tooling.

## Tech Stack

- Python 3.14+
- FastAPI and Starlette
- Pydantic and pydantic-settings
- SQLAlchemy and Alembic
- HTTPX
- Cryptography
- Playwright
- Pytest, pytest-cov, Ruff, and mypy

## Setup

Create a virtual environment and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install -e .
```

For local configuration, copy the example environment file and edit values as
needed:

```bash
cp .env.example .env
```

The default database URL is `sqlite:///./app.db`.

## CLI Usage

Show help:

```bash
security-scanner --help
```

Run a scan with table output:

```bash
security-scanner --url https://example.com --format table
```

Print JSON:

```bash
security-scanner --url https://example.com --format json
```

Save a JSON report:

```bash
security-scanner --url https://example.com --output artifacts/example-scan.json
```

You can also run the package module directly:

```bash
python -m security_scanner --url https://example.com --verbose
```

## API Usage

Start the development server:

```bash
uvicorn security_scanner.main:app --reload
```

The API runs at:

```text
http://127.0.0.1:8000
```

Interactive docs are available at:

```text
http://127.0.0.1:8000/docs
```

Common routes:

```text
GET  /api/v1/health
POST /api/v1/scan
POST /api/v1/scans
GET  /api/v1/scans
GET  /api/v1/scans/{scan_id}
POST /api/v1/auth/register
POST /api/v1/auth/login
GET  /api/v1/auth/me
POST /api/v1/scrape
```

Start a scan:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

Check scan status using the returned `scan_id`:

```bash
curl http://127.0.0.1:8000/api/v1/scans/<scan_id>
```

## Database

Alembic is configured with `alembic.ini` and migrations live under
`security_scanner/db/migrations`.

Run migrations with:

```bash
alembic upgrade head
```

## Tests And Quality

Run the test suite:

```bash
pytest
```

Run coverage:

```bash
pytest --cov=security_scanner
```

Run linting and type checks:

```bash
ruff check .
mypy security_scanner tests
```

## Project Structure

```text
security_scanner/
  api/v1/          FastAPI routes and dependencies
  core/            Settings, logging, security helpers, exception handling
  db/              SQLAlchemy session setup and Alembic migrations
  models/          Domain and database models
  repositories/    Database access helpers
  reports/         JSON and table formatters
  scanner/         Scanner runner, HTTP client, and checks
  schemas/         Pydantic request and response schemas
  scraper/         Playwright scraper support
  services/        Scan job orchestration and application services
  tasks/           Task entry points
  utils/           URL, TLS, validation, and fetch utilities

tests/
  api/
  integration/
  unit/

docs/
  api.md
  architecture.md
  setup.md
```

## More Documentation

- `docs/setup.md` for local setup notes.
- `docs/api.md` for API design details.
- `docs/architecture.md` for application structure.
- `docs/security_misconfiguration_scanner_learning_guide.md` for the learning
  guide.
