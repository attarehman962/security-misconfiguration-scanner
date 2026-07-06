# Security Misconfiguration Scanner

A Python security scanner for learning, portfolio work, and authorized testing.
It runs as both a command-line tool and a FastAPI service, checks target URLs for
common web security misconfigurations, and includes a scraping workflow that can
persist extracted job listings in the database.

This is not a replacement for a professional penetration test. Only scan systems
you own or have explicit permission to test.

## Features

- CLI scanner with table or JSON output.
- FastAPI app with versioned routes under `/api/v1`.
- Background scan jobs with status lookup.
- Security header checks for HSTS, CSP, X-Frame-Options, and related headers.
- Exposure checks for weak CORS, server banners, `/.env`, `/.git/config`, and
  directory listing indicators.
- HTTPS/TLS certificate expiry checks.
- JWT-based registration, login, and current-user lookup.
- Live URL scraping with static HTML extraction or Playwright rendering.
- Saved scraped-job results with per-user database isolation.
- CSV export for saved scraped results.
- SQLAlchemy models plus Alembic migrations for users, scans, findings, and
  scraped jobs.
- Pytest, Ruff, mypy, and coverage tooling.

## Tech Stack

- Python 3.14+
- FastAPI and Starlette
- Pydantic and pydantic-settings
- SQLAlchemy and Alembic
- HTTPX
- python-jose and passlib/bcrypt
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

Copy the example environment file and edit values as needed:

```bash
cp .env.example .env
```

The default database URL is `sqlite:///./app.db`. Apply migrations before using
database-backed API features:

```bash
alembic upgrade head
```

If you use JavaScript scraping, install Playwright browsers:

```bash
python -m playwright install chromium
```

## Docker Compose

The Docker Compose files live in the `docker/` directory:

```text
docker/docker-compose.yml
docker/docker-compose.ci.yml
```

Start the app, Postgres database, and integration target site:

```bash
POSTGRES_PORT=55432 docker compose -f docker/docker-compose.yml -f docker/docker-compose.ci.yml up -d --build app db target-site
```

The app is available at `http://localhost:8000`, and the target site is
available at `http://localhost:8099`.

Check container status:

```bash
POSTGRES_PORT=55432 docker compose -f docker/docker-compose.yml -f docker/docker-compose.ci.yml ps
```

View logs:

```bash
POSTGRES_PORT=55432 docker compose -f docker/docker-compose.yml -f docker/docker-compose.ci.yml logs -f
```

Shut down the stack and remove the database volume:

```bash
docker compose -f docker/docker-compose.yml -f docker/docker-compose.ci.yml down -v
```

Run the full Docker-backed integration flow:

```bash
scripts/run_integration.sh
```

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

The API runs at `http://127.0.0.1:8000`. Interactive docs are available at
`http://127.0.0.1:8000/docs`.

Common routes:

```text
GET  /api/v1/health
POST /api/v1/scans
GET  /api/v1/scans
GET  /api/v1/scans/{scan_id}
GET  /api/v1/scans/{scan_id}/report
POST /api/v1/auth/register
POST /api/v1/auth/login
GET  /api/v1/auth/me
POST /api/v1/scrape/
POST /api/v1/scrape/results
GET  /api/v1/scrape/results
GET  /api/v1/scrape/results/export
```

Start a scan:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://example.com"}'
```

Run a live scrape without storing the result:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scrape/ \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/jobs", "css_selector": "a", "use_javascript": false}'
```

Register and login before saving scraped jobs:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "learner@example.com", "password": "change-me-123"}'

TOKEN=$(curl -s -X POST http://127.0.0.1:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "learner@example.com", "password": "change-me-123"}' \
  | python -c "import json,sys; print(json.load(sys.stdin)['access_token'])")
```

Save scraped job records to the database:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scrape/results \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '[
    {
      "source_url": "https://jobs.example.com/1",
      "title": "Security Engineer",
      "company": "Example Labs",
      "location": "Remote"
    }
  ]'
```

List saved scraped jobs:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8000/api/v1/scrape/results?company=Example&limit=50"
```

Export saved scraped jobs as CSV:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8000/api/v1/scrape/results/export
```

## Scraped Data Persistence

Live scraping and stored scraped jobs share one service module:
`security_scanner/services/scraping_service.py`.

The live scrape path returns extracted items immediately and does not write to
the database. The saved-results path accepts normalized job records, stores them
in the `scraped_jobs` table, skips duplicates for the same user/source/title,
and returns only newly inserted rows.

Important files:

```text
security_scanner/api/v1/routes/scrapes.py      HTTP routes
security_scanner/services/scraping_service.py  live scraping and saved-job service logic
security_scanner/crud/scraped_job.py           database insert/query helpers
security_scanner/models/scraped_job.py         SQLAlchemy table model
security_scanner/schemas/scraped_job.py        Pydantic request/response models
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
  crud/            Database-focused insert/query helpers
  db/              SQLAlchemy session setup and Alembic migrations
  models/          Domain models and SQLAlchemy records
  repositories/    User repository helpers
  reporting/       PDF, JSON, table, and CSV helpers
  scanner/         Scanner runner, HTTP client, and checks
  schemas/         Pydantic request and response schemas
  scraper/         Playwright scraper support and scrape data classes
  services/        Application service layer
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
