# Security Misconfiguration Scanner API

This document describes the current FastAPI surface for scans, authentication,
live scraping, and persisted scraped-job results.

The application is created in `security_scanner/main.py` and mounts every route
under `/api/v1`.

## Running Locally

```bash
source .venv/bin/activate
alembic upgrade head
uvicorn security_scanner.main:app --reload
```

OpenAPI docs:

```text
http://127.0.0.1:8000/docs
```

## Error Shape

Validation errors are normalized by `security_scanner/core/exceptions.py`.
Expected API errors use JSON responses with either FastAPI's `detail` field or
the project validation shape:

```json
{
  "error": "validation_error",
  "detail": [
    {
      "field": "url",
      "message": "Input should be a valid URL"
    }
  ]
}
```

## Health

### `GET /api/v1/health`

Returns application health status.

Example:

```bash
curl http://127.0.0.1:8000/api/v1/health
```

## Authentication

Saved scraped-job results are user-owned, so the save, list, and export
endpoints require a bearer token.

### `POST /api/v1/auth/register`

Request:

```json
{
  "email": "learner@example.com",
  "password": "change-me-123"
}
```

Response:

```json
{
  "id": 1,
  "email": "learner@example.com",
  "is_active": true
}
```

### `POST /api/v1/auth/login`

Request:

```json
{
  "email": "learner@example.com",
  "password": "change-me-123"
}
```

Response:

```json
{
  "access_token": "<jwt>",
  "token_type": "bearer"
}
```

Use the token as:

```text
Authorization: Bearer <jwt>
```

### `GET /api/v1/auth/me`

Returns the authenticated user.

## Scanning

The scanner has both immediate and job-style endpoints.

### `POST /api/v1/scan`

Starts a scan for a URL and returns scan output according to the route contract
in `security_scanner/api/v1/routes/scans.py`.

Example:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

### `POST /api/v1/scans`

Creates a background scan job.

Request:

```json
{
  "target_url": "https://example.com"
}
```

Typical accepted response:

```json
{
  "scan_id": "scan_...",
  "status": "pending",
  "status_url": "/api/v1/scans/scan_..."
}
```

### `GET /api/v1/scans`

Lists scan jobs.

### `GET /api/v1/scans/{scan_id}`

Returns one scan job and, when complete, its result.

## Live Scraping

Live scraping extracts content from a target page and returns it immediately. It
does not write to the database.

Route implementation:

```text
security_scanner/api/v1/routes/scrapes.py
security_scanner/services/scraping_service.py
security_scanner/schemas/scrape.py
security_scanner/scraper/
```

### `POST /api/v1/scrape/`

Request:

```json
{
  "url": "https://example.com/jobs",
  "css_selector": "a.job-link",
  "use_javascript": false
}
```

Fields:

- `url`: required page URL.
- `css_selector`: optional selector for readable elements.
- `use_javascript`: when true, render with Playwright before extracting text.

Response:

```json
{
  "source_url": "https://example.com/jobs",
  "success": true,
  "items": [
    {
      "title": "Security Engineer",
      "price": null,
      "url": "https://example.com/jobs/1"
    }
  ],
  "scraped_at": "2026-06-26T12:00:00Z",
  "error_message": null
}
```

Recoverable scrape failures, such as a timeout from the target site, return
`success: false` and an `error_message` in the response body. Infrastructure
errors in the scraper service return HTTP 500.

## Persisted Scraped Jobs

Persisted scraped jobs store normalized job listings in the database. These
routes require authentication and are scoped to the current user.

Route implementation:

```text
security_scanner/api/v1/routes/scrapes.py
security_scanner/services/scraping_service.py
security_scanner/crud/scraped_job.py
security_scanner/models/scraped_job.py
security_scanner/schemas/scraped_job.py
```

Database table:

```text
scraped_jobs
  id
  user_id
  source_url
  title
  company
  location
  date_posted
  scraped_at
```

The model and migration enforce a unique constraint across:

```text
user_id, source_url, title
```

That means two users can save the same job independently, while the same user
cannot store the same source/title combination twice.

### `POST /api/v1/scrape/results`

Saves scraped job listings for the authenticated user.

Request:

```json
[
  {
    "source_url": "https://jobs.example.com/1",
    "title": "Security Engineer",
    "company": "Example Labs",
    "location": "Remote",
    "date_posted": "2026-06-26T09:00:00Z"
  }
]
```

Response status: `201 Created`

Response body contains only newly inserted records. Duplicates are skipped and
not returned.

```json
[
  {
    "id": 1,
    "source_url": "https://jobs.example.com/1",
    "title": "Security Engineer",
    "company": "Example Labs",
    "location": "Remote",
    "date_posted": "2026-06-26T09:00:00Z",
    "scraped_at": "2026-06-26T12:00:00Z"
  }
]
```

### `GET /api/v1/scrape/results`

Lists saved scraped jobs for the authenticated user.

Query parameters:

- `company`: optional case-insensitive partial company filter.
- `location`: optional case-insensitive partial location filter.
- `title`: optional case-insensitive partial title filter.
- `skip`: offset for pagination, default `0`.
- `limit`: page size, default `100`, maximum `500`.

Example:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8000/api/v1/scrape/results?company=Example&limit=25"
```

### `GET /api/v1/scrape/results/export`

Streams all saved scraped jobs for the authenticated user as CSV.

CSV columns:

```text
id,source_url,title,company,location,date_posted,scraped_at
```

Example:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8000/api/v1/scrape/results/export
```

## Data Flow Summary

Live scrape:

```text
HTTP request
  -> routes/scrapes.py:scrape_url
  -> ScrapingService.scrape_url
  -> static HTML parser or Playwright
  -> schemas/scrape.py:scrape_result_to_response
  -> JSON response
```

Saved scraped jobs:

```text
HTTP request with bearer token
  -> get_current_user
  -> routes/scrapes.py:save_scraped_jobs
  -> scraping_service.save_jobs
  -> crud/scraped_job.py:create_scraped_job
  -> models/scraped_job.py:ScrapedJob
  -> database row
  -> ScrapedJobOut response
```

CSV export:

```text
HTTP request with bearer token
  -> routes/scrapes.py:export_scraped_jobs
  -> scraping_service.stream_jobs_csv
  -> cursor batches from get_scraped_jobs
  -> StreamingResponse
```
