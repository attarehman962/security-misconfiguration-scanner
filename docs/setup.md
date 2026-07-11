# Setup

This guide covers local installation, database setup, browser setup for dynamic
scraping, and common verification commands.

## Python Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install -e .
```

The project targets Python 3.14+.

## Environment Variables

Copy the example environment file:

```bash
cp .env.example .env
```

Important settings:

```text
POSTGRES_PORT=5432
DATABASE_URL=postgresql+psycopg://postgres:postgres@localhost:5432/security_scanner
JWT_SECRET_KEY=change-this-in-real-deployments
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
```

Use a long random `JWT_SECRET_KEY` outside local development.

## Database

Start PostgreSQL, then apply migrations:

```bash
POSTGRES_PORT=5432 docker compose -f docker/docker-compose.yml up -d db
```

Apply migrations:

```bash
alembic upgrade head
```

The database includes tables for users, scans, findings, and scraped jobs.

The scraped-job table stores:

```text
id
user_id
source_url
title
company
location
date_posted
scraped_at
```

The unique constraint on `user_id`, `source_url`, and `title` keeps each user's
saved scraped data idempotent.

## Playwright Browser Setup

Static scraping works through HTTPX and the standard-library HTML parser.

JavaScript scraping requires Playwright's Chromium browser:

```bash
python -m playwright install chromium
```

## Run The API

```bash
uvicorn security_scanner.main:app --reload
```

Open:

```text
http://127.0.0.1:8000/docs
```

## Run The CLI

```bash
security-scanner --url https://example.com --format table
security-scanner --url https://example.com --format json
python -m security_scanner --url https://example.com --verbose
```

## Verify Scraped Data Persistence

Start the server, register, login, and save scraped jobs:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "learner@example.com", "password": "change-me-123"}'

TOKEN=$(curl -s -X POST http://127.0.0.1:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "learner@example.com", "password": "change-me-123"}' \
  | python -c "import json,sys; print(json.load(sys.stdin)['access_token'])")

curl -X POST http://127.0.0.1:8000/api/v1/scrape/results \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '[{"source_url":"https://jobs.example.com/1","title":"Security Engineer"}]'
```

Then list saved rows:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8000/api/v1/scrape/results
```

## Tests

Run all tests:

```bash
pytest
```

Run the production-style integration flow against Docker Compose:

```bash
scripts/run_integration.sh
```

The integration script starts PostgreSQL, the FastAPI app, and the deterministic
nginx target site used by scanner/scraper tests.
It defaults PostgreSQL to host port `5432`; override `APP_PORT`, `POSTGRES_PORT`, or
`TARGET_SITE_PORT` when your machine or CI runner needs different ports.
Set `SKIP_DOCKER_BUILD=true` to reuse already-built images during local reruns
when Docker Hub is temporarily unavailable.

Run the scraping and scraped-results tests only:

```bash
pytest tests/unit/test_scraping_service.py tests/api/test_scrapes.py \
  tests/unit/test_scrapes_route.py tests/unit/test_scrape_results.py --no-cov
```

The project enforces total coverage in normal pytest runs, so focused subsets
should use `--no-cov` when you only want quick local feedback.

## Quality Commands

```bash
ruff check .
mypy security_scanner tests
pytest --cov=security_scanner
```
