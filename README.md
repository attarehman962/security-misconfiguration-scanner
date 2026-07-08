# Security Misconfiguration Scanner

[![CI](https://github.com/attarehman962/security-misconfiguration-scanner/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/attarehman962/security-misconfiguration-scanner/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.139-009688)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-336791)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED)
![pytest](https://img.shields.io/badge/tests-pytest-0A9EDC)
![GitHub Actions](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF)

Python/FastAPI security scanner for headers, CORS, exposed files, SSL issues,
PDF reports, scraping, Docker, PostgreSQL, and CI.

This is a learning and portfolio project, not a replacement for a professional
penetration test. Only scan systems you own or have explicit permission to test.

## Repository Metadata

Description:

```text
Python/FastAPI security scanner for headers, CORS, exposed files, SSL issues, PDF reports, scraping, Docker, PostgreSQL, and CI.
```

GitHub topics:

```text
python
fastapi
postgresql
sqlalchemy
alembic
security-scanner
security-automation
web-security
docker
pytest
github-actions
web-scraping
playwright
jwt-authentication
pdf-report
```

## Features

- 10+ security checks with severity scoring and a total risk score.
- CLI scanner with table and JSON output.
- JWT-authenticated REST API under `/api/v1`.
- Background scan jobs with persistent scan history.
- PostgreSQL storage for users, scans, findings, and scraped jobs.
- PDF report generation for completed scans.
- Web scraping module with static HTML parsing and optional Playwright rendering.
- Saved scraped-job results with per-user isolation and CSV export.
- Dockerized app, database, and intentionally misconfigured target site.
- CI/CD with GitHub Actions, pytest, Ruff, mypy, and coverage tooling.

## Tech Stack

| Area     | Tools                                       |
| -------- | ------------------------------------------- |
| Language | Python 3.11+                                |
| API      | FastAPI, Starlette, Uvicorn                 |
| Database | PostgreSQL, SQLAlchemy, Alembic             |
| Auth     | JWT, python-jose, passlib, bcrypt           |
| Scanner  | HTTPX, Cryptography, custom security checks |
| Scraping | Static HTML extraction, Playwright support  |
| Reports  | ReportLab PDF generation, CSV export        |
| Testing  | pytest, pytest-asyncio, pytest-cov          |
| Quality  | Ruff, mypy                                  |
| Runtime  | Docker Compose                              |
| CI       | GitHub Actions                              |

## Architecture

```text
                         +-----------------------------+
                         | Security Scanner CLI        |
                         | python -m security_scanner  |
                         +--------------+--------------+
                                        |
                                        v
+----------------+       +-------------+--------------+       +----------------+
| Target Website | <---- | FastAPI app /api/v1        | ----> | PostgreSQL     |
| or Target Site |       | auth, scans, scrape, PDF   |       | users/scans    |
+----------------+       +-------------+--------------+       | findings/jobs  |
                                        |                      +----------------+
                                        v
                         +--------------+--------------+
                         | PDF Report Generator        |
                         | completed scan -> PDF       |
                         +-----------------------------+
```

The Docker integration stack adds a local `target-site` container that
intentionally exposes weak headers, permissive CORS, and a test `.env` file so
the scanner has known misconfigurations to detect.

## Requirements

For the Docker quick start, you only need:

- Docker with the Compose plugin.
- A free host port for the API, default `8000`.
- A free host port for the target site, default `8099`.
- A free host port for PostgreSQL. The examples use `55432` to avoid conflicts
  with a local PostgreSQL server on `5432`.

For local Python development without Docker, use Python 3.11+ and install the
project dependencies from `requirements.txt` and `requirements-dev.txt`.

## Quick Start

Clone the repository and enter the project directory:

```bash
git clone https://github.com/attarehman962/security-misconfiguration-scanner.git
cd security-misconfiguration-scanner
```

Start the Docker stack:

```bash
POSTGRES_PORT=5432 docker compose -f docker/docker-compose.yml -f docker/docker-compose.ci.yml up -d --build app db target-site
```

The app runs at:

```text
API:        http://localhost:8000
API docs:   http://localhost:8000/docs
Target:     http://localhost:8099
Postgres:   localhost:5432
```

Check container status:

```bash
POSTGRES_PORT=5432 docker compose -f docker/docker-compose.yml -f docker/docker-compose.ci.yml ps
```

Shut down the stack and remove the test database volume:

```bash
docker compose -f docker/docker-compose.yml -f docker/docker-compose.ci.yml down -v
```

You do not need to copy `.env.example` for the Docker quick start. If you already
have a local `.env` file with `DATABASE_URL=sqlite:///./app.db`, remove that
line or override it before starting Docker, otherwise Compose will pass SQLite
to the app instead of the PostgreSQL service.

## Docker Compose

The Docker Compose files live in the `docker/` directory:

```text
docker/docker-compose.yml      base app, database, and optional Playwright service
docker/docker-compose.ci.yml   integration target site and CI/test overrides
```

The CI compose override runs database migrations before starting Uvicorn:

```text
alembic upgrade head && uvicorn security_scanner.main:app --host 0.0.0.0 --port 8000
```

View logs:

```bash
POSTGRES_PORT=5432 docker compose -f docker/docker-compose.yml -f docker/docker-compose.ci.yml logs -f
```

Run the full Docker-backed integration flow:

```bash
scripts/run_integration.sh
```

## CLI Usage

After local installation, show CLI help:

```bash
security-scanner --help
```

Run a scan from inside the app container against the Docker target site:

```bash
POSTGRES_PORT=5432 docker compose -f docker/docker-compose.yml -f docker/docker-compose.ci.yml exec app \
  python -m security_scanner --url http://target-site:80
```

After local installation, run a scan with table output:

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

The CLI currently writes table or JSON output. PDF reports are generated through
the API for completed background scans.

## API Endpoints

| Method | Endpoint                         | Auth | Purpose                          |
| ------ | -------------------------------- | ---- | -------------------------------- |
| `GET`  | `/api/v1/health`                 | No   | Health check                     |
| `POST` | `/api/v1/auth/register`          | No   | Register a user                  |
| `POST` | `/api/v1/auth/login`             | No   | Login and receive a JWT          |
| `GET`  | `/api/v1/auth/me`                | Yes  | Return the current user          |
| `POST` | `/api/v1/scans`                  | Yes  | Start a background scan          |
| `GET`  | `/api/v1/scans`                  | Yes  | List the current user's scans    |
| `GET`  | `/api/v1/scans/{scan_id}`        | Yes  | Get scan status and findings     |
| `GET`  | `/api/v1/scans/{scan_id}/report` | Yes  | Download a completed scan as PDF |
| `POST` | `/api/v1/scrape/`                | No   | Scrape a URL immediately         |
| `POST` | `/api/v1/scrape/results`         | Yes  | Save scraped job rows            |
| `GET`  | `/api/v1/scrape/results`         | Yes  | List saved scraped jobs          |
| `GET`  | `/api/v1/scrape/results/export`  | Yes  | Export saved scraped jobs as CSV |

Interactive API documentation is available after startup:

```text
http://localhost:8000/docs
```

## API Examples

Register a user:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "learner@example.com", "password": "StrongPassword123!", "full_name": "Learner"}'
```

Login and capture the token:

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "learner@example.com", "password": "StrongPassword123!"}' \
  | python -c "import json,sys; print(json.load(sys.stdin)['access_token'])")
```

Start a scan against the Docker target site:

```bash
SCAN_ID=$(curl -s -X POST http://127.0.0.1:8000/api/v1/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://target-site:80"}' \
  | python -c "import json,sys; print(json.load(sys.stdin)['scan_id'])")
```

Check scan status:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8000/api/v1/scans/$SCAN_ID"
```

Download the PDF report after the scan completes:

```bash
mkdir -p artifacts

curl -L -H "Authorization: Bearer $TOKEN" \
  -o artifacts/target-site-scan.pdf \
  "http://127.0.0.1:8000/api/v1/scans/$SCAN_ID/report"
```

Run a live scrape without storing the result:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scrape/ \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/jobs", "css_selector": "a", "use_javascript": false}'
```

Save scraped job records:

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

Export saved scraped jobs as CSV:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8000/api/v1/scrape/results/export
```

## Example Output

Terminal output for the intentionally misconfigured Docker target looks like:

```text
Scan result for: http://target-site
Total score: 54

Strict-Transport-Security  Fail  High    Missing Strict-Transport-Security header.
Content-Security-Policy    Fail  High    Missing Content-Security-Policy header.
Weak CORS policy           Fail  High    Access-Control-Allow-Origin is set to '*'.
Exposed .env file          Fail  High    http://target-site:80/.env returned HTTP 200.
ssl                        Fail  High    The target is not using HTTPS.
```

The sample PDF generated during local testing is written to:

```text
artifacts/target-site-scan.pdf
```

## Optional Portfolio Assets

Screenshots and demo videos are not required to run or test the project. If you
want them for a portfolio page, useful captures are:

| View                 | Suggested file                       | Notes                                                     |
| -------------------- | ------------------------------------ | --------------------------------------------------------- |
| Terminal scan output | `docs/screenshots/terminal-scan.png` | Capture the CLI table output for `http://target-site:80`. |
| API docs page        | `docs/screenshots/api-docs.png`      | Capture `http://localhost:8000/docs`.                     |
| Sample PDF report    | `docs/screenshots/pdf-report.png`    | Capture a page from `artifacts/target-site-scan.pdf`.     |

A short demo can follow this flow:

1. Start Docker Compose.
2. Open `http://localhost:8000/docs`.
3. Register and login.
4. Start a scan against `http://target-site:80`.
5. Show findings and download the PDF report.
6. Run the CLI scan from the app container.

## Local Python Setup

For local development without Docker, create a virtual environment and install
dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
python -m pip install -e .
```

Copy the environment template for local development:

```bash
cp .env.example .env
```

Apply database migrations before using database-backed API features:

```bash
alembic upgrade head
```

Start the development server:

```bash
uvicorn security_scanner.main:app --reload
```

Install Playwright browsers if you use JavaScript rendering for scraping:

```bash
python -m playwright install chromium
```

## Tests And Quality

Run API and unit tests:

```bash
.venv/bin/python -m pytest -q tests/api tests/unit
```

With the Docker stack running, run the Docker-backed integration test:

```bash
BASE_URL=http://127.0.0.1:8000 \
TARGET_SCAN_URL=http://target-site \
.venv/bin/python -m pytest -q tests/integration
```

Run the full integration script, including Docker startup, readiness checks,
pytest, logs, and cleanup:

```bash
scripts/run_integration.sh
```

Run coverage:

```bash
.venv/bin/python -m pytest --cov=security_scanner
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

docker/
  Dockerfile
  Dockerfile.playwright
  docker-compose.yml
  docker-compose.ci.yml

docs/
  api.md
  architecture.md
  setup.md
```

## Security Notes

- Only scan systems you own or have authorization to test.
- The included `target-site` is intentionally misconfigured for safe local
  testing.
- Do not use the CI/demo secrets in production.
- Replace `JWT_SECRET_KEY` with a strong random value before deploying.
