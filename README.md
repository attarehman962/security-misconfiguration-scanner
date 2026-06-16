# Security Misconfiguration Scanner

## Purpose

Security Misconfiguration Scanner is a Python project for checking common web
security misconfigurations on an authorized target URL. The repository contains
the original command-line scanner package and a new FastAPI app in `app/`.

The CLI fetches one URL, inspects response headers, checks selected exposure
risks, checks basic TLS certificate health, calculates a simple score, and
prints the result as a terminal table or JSON.

This project is designed for learning, portfolio work, and safe authorized
security testing. It is not a replacement for a professional penetration test.

## Features

The project currently includes:

- URL fetch success or failure.
- Final URL after redirects.
- HTTP response status code, headers, and body.
- Browser security headers.
- Weak CORS configuration.
- Server banner and `X-Powered-By` exposure.
- Parent directory listing exposure.
- Public `/.env` exposure.
- Public `/.git/config` exposure.
- HTTP vs HTTPS usage.
- TLS certificate lookup, expiry, and near-expiry status.
- A simple total score from `0` to `100`.
- Table output for humans and JSON output for automation.
- JSON report saving with `--output`.
- A FastAPI app under `app/` with health, scan, and scan history routes.

## Tech Stack

### CLI Scanner

- Python `3.14+`
- `httpx` for HTTP requests
- `cryptography` for TLS certificate parsing
- `argparse` for the command-line interface
- `dataclasses` and `Enum` for typed scanner models
- `pytest` and `pytest-cov` for tests and coverage
- `mypy` for static type checking
- `ruff` for linting

### API App

- FastAPI for HTTP routes and interactive API docs
- Pydantic for request and response schemas
- Uvicorn/FastAPI development server
- Pytest with FastAPI `TestClient`

## Installation

### CLI Scanner

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Install the package in editable mode so the `security-scanner` command is
available inside your virtual environment:

```bash
python -m pip install -e .
```

### API App

The API app has its own dependency file and tests inside `app/`:

```bash
cd app
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Usage Examples

### CLI Scanner

Show help:

```bash
security-scanner --help
```

Run the scanner with table output:

```bash
security-scanner --url https://example.com --format table
```

Print JSON:

```bash
security-scanner --url https://example.com --format json
```

Save JSON to a file:

```bash
security-scanner --url https://example.com --output result.json
```

Print progress messages to stderr:

```bash
security-scanner --url https://example.com --verbose
```

You can also run the package as a module:

```bash
python -m security_scanner --url https://example.com --format table
```

### API App

From the `app/` directory, start the API development server:

```bash
fastapi dev app/main.py
```

Or run it with Uvicorn:

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

Example API scan request:

```bash
curl -X POST http://127.0.0.1:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

## Project Structure

```text
security_scanner/
  __init__.py          Public package exports
  __main__.py          Entry point for python -m security_scanner
  cli.py               argparse CLI, output selection, file saving
  app/                 FastAPI application, DB models, migrations, API schemas
  core/
    exceptions.py      Project exception types
    logging.py         Logging configuration
    models.py          Severity, Status, Finding, ScanResult
  scanning/
    runner.py          Main orchestration through run_full_scan()
    validators.py      CLI URL validation
    url_utils.py       Shared URL normalization and root-path helpers
    url_fetcher.py     Main target fetcher using httpx.Client
    http_client.py     Small safe fetch helper for extra exposure paths
    ssl_utils.py       TLS certificate expiry helpers
  checks/
    security_headers.py
                      Security header checks
    exposure.py        CORS, banner, directory, .env, and .git checks
  output/
    serializers.py     Dataclass/enum to JSON-safe dictionaries
    formatters.py      JSON and terminal table formatting
  scraping/            Dynamic scraping support

tests/
  api/
  checks/test_security_headers.py
  test_cli.py
  test_exposure_checks.py
  test_formatters.py
  test_http_client.py
  test_logging_config.py
  test_main.py
  test_models.py
  test_runner.py
  test_serializers.py
  test_ssl_utils.py
  test_url_fetcher.py
  test_url_utils.py
  test_validators.py
  test_package_exports.py
  app/
    main.py            FastAPI application factory
    core/config.py     API settings
    routers/
      auth.py          Placeholder auth router
      scan.py          Health, scan, and scan history routes
      scrape.py        Placeholder scraping router
    schemas/
      auth.py          Auth schema module
      error.py         Custom validation error schemas
      scan.py          Health and scan request/response schemas
    services/
      scanner_service.py
                      Mock scanner response service
      scraping_service.py
                      Placeholder scraping service
  tests/
    test_health.py
    test_scan_routes.py
```

## Complete Workflow

```text
1. Terminal user
   security-scanner --url https://example.com --format table

2. security_scanner/__main__.py
   Calls security_scanner.cli.main().

3. security_scanner/cli.py
   Builds argparse parser.
   Reads --url, --format, and --output.
   Calls validate_url() before scanning starts.
   Calls run_full_scan().

4. security_scanner/validators.py
   Rejects invalid URLs:
   - missing scheme
   - unsupported scheme
   - spaces
   - missing hostname
   - fragments such as #section

5. security_scanner/url_utils.py
   Provides shared URL helpers:
   - normalize hostnames into URLs for fetchers
   - reject malformed/unsupported URLs
   - build root-relative paths such as /.env

6. security_scanner/scanning/runner.py
   Coordinates the scan.
   Calls UrlFetcher().fetch(url).
   Adds header findings.
   Adds exposure findings.
   Adds SSL/TLS finding.
   Calculates total score.
   Returns ScanResult.

7. security_scanner/scanning/url_fetcher.py
   Fetches the main target.
   Captures final URL, status code, headers, body, SSL expiry, and errors.

8. security_scanner/checks/security_headers.py
   Checks common browser security headers.

9. security_scanner/checks/exposure.py
   Checks CORS, server banners, X-Powered-By, directory listing, .env, and
   .git/config exposure.

10. security_scanner/scanning/http_client.py
   Performs safe small fetches for extra paths such as /.env and /.git/config.

11. security_scanner/scanning/ssl_utils.py
    Reads TLS certificate expiry for HTTPS targets.

12. security_scanner/core/models.py
    Stores all results as typed dataclasses and enums.

13. security_scanner/output/serializers.py
    Converts dataclasses and enums into JSON-safe dictionaries.

14. security_scanner/output/formatters.py
    Formats the result as JSON or a terminal table.

15. security_scanner/cli.py
    Prints output and optionally writes result.json.
```

Short flow:

```text
__main__.py
-> cli.py
-> scanning/validators.py
-> scanning/url_utils.py
-> scanning/runner.py
-> scanning/url_fetcher.py
-> checks/security_headers.py
-> checks/exposure.py
-> scanning/ssl_utils.py
-> core/models.py
-> output/serializers.py
-> output/formatters.py
-> terminal or JSON file
```

## CLI Details

Supported options:

```text
--url       Required target URL. Must start with http:// or https://.
--format    Output format. Choices: table, json. Default: table.
--output    Optional path to save JSON output.
--verbose   Print progress messages to stderr.
```

Exit codes:

```text
0   Scan completed and output was printed.
1   Scanner handled a runtime failure or could not write the output file.
2   argparse rejected invalid CLI input such as a bad URL or bad format.
```

Examples:

```bash
security-scanner --url https://example.com
security-scanner --url https://example.com --format table
security-scanner --url https://example.com --format json
security-scanner --url https://example.com --output result.json
security-scanner --url https://example.com --verbose
python -m security_scanner --url https://example.com
```

Invalid format values are rejected by `argparse` before scanning:

```bash
security-scanner --url https://example.com --format xml
```

Invalid URLs are rejected by `validate_url()` before network requests are made.

## Sample Output

### Table Output

```text
Scan result for: https://example.com
Timestamp: 2026-06-08T12:00:00+00:00
Total score: 80

+---------------------------+--------+----------+-------------------------+
| Check                     | Status | Severity | Description             |
+---------------------------+--------+----------+-------------------------+
| Strict-Transport-Security | Fail   | High     | HSTS header is missing. |
+---------------------------+--------+----------+-------------------------+
```

### JSON Output

```json
{
  "findings": [
    {
      "check_name": "Content-Security-Policy",
      "description": "Missing Content-Security-Policy header.",
      "remediation": "Add Content-Security-Policy header.",
      "severity": "High",
      "status": "Fail"
    }
  ],
  "timestamp": "2026-06-08T12:00:00+00:00",
  "total_score": 80,
  "url": "https://example.com"
}
```

## Data Models

### Severity

`Severity` is an enum, not a raw string type.

```python
from security_scanner.models.scan import Severity

Severity.INFO
Severity.LOW
Severity.MEDIUM
Severity.HIGH
```

The enum prevents spelling mistakes in code. Serializers convert it to plain
JSON strings such as `"High"`.

### Status

`Status` is an enum for whether a check passed or failed.

```python
from security_scanner.models.scan import Status

Status.PASS
Status.FAIL
```

Serializers convert it to plain JSON strings such as `"Pass"` and `"Fail"`.

### Finding

A `Finding` is one check result.

```python
from security_scanner.models.scan import Finding, Severity, Status

finding = Finding(
    check_name="Content-Security-Policy",
    status=Status.FAIL,
    severity=Severity.HIGH,
    description="Missing Content-Security-Policy header.",
    remediation="Add a Content-Security-Policy header.",
)
```

Fields:

- `check_name`: Name of the header or check.
- `status`: `Status.PASS` if the check passed, `Status.FAIL` if it failed.
- `severity`: `Severity.INFO`, `LOW`, `MEDIUM`, or `HIGH`.
- `description`: Human-readable result.
- `remediation`: Suggested fix.

### UrlScanResult

`UrlScanResult` stores the main target fetch data:

```text
input_url
final_url
status_code
headers
body
ssl_expiry_utc
error
```

The `body` field is required because exposure checks need to inspect the
response body for directory listing patterns.

### FetchResult

`FetchResult` in `security_scanner/http_client.py` is a smaller safe fetch result used
for extra paths:

```text
url
status_code
headers
body
```

It is used by exposure checks for paths such as:

```text
/.env
/.git/config
```

### ScanResult

`ScanResult` is the final result returned by the scanner:

```python
from datetime import datetime, timezone

from security_scanner.models.scan import ScanResult

result = ScanResult(
    url="https://example.com",
    timestamp=datetime.now(timezone.utc),
    total_score=80,
    findings=[finding],
)
```

## Checks

### Security Header Checks

`security_scanner/checks/security_headers.py` checks:

- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`

Header lookup is case-insensitive because real HTTP header names can arrive in
different casing.

Example:

```bash
python - <<'PY'
from security_scanner.scanner.checks.security_headers import findings_to_json, run_header_checks

headers = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Frame-Options": "DENY",
}

findings = run_header_checks(headers)
print(findings_to_json(findings))
PY
```

### Exposure Checks

`security_scanner/checks/exposure.py` checks:

- Weak wildcard CORS on non-public APIs.
- Server header version exposure.
- `X-Powered-By` framework/runtime exposure.
- Parent directory listing markers in the body.
- Public `/.env`.
- Public `/.git/config`.

Example:

```bash
python - <<'PY'
from security_scanner.scanner.checks.exposure import check_weak_cors
from security_scanner.models.scan import Status

finding = check_weak_cors({"Access-Control-Allow-Origin": "*"})
print(finding.status is Status.FAIL)
print(finding.severity)
PY
```

Expected output:

```text
True
Severity.HIGH
```

Example for `/.env`:

```bash
python - <<'PY'
from collections.abc import Mapping
from dataclasses import dataclass

from security_scanner.scanner.checks.exposure import check_exposed_env
from security_scanner.models.scan import Status


@dataclass
class FakeResponse:
    status_code: int
    headers: Mapping[str, str]
    body: str


def fake_fetcher(url: str, timeout: int) -> FakeResponse:
    return FakeResponse(status_code=200, headers={}, body="SECRET_KEY=test")


finding = check_exposed_env("https://example.com", fake_fetcher)
print(finding.status is Status.FAIL)
print(finding.severity)
PY
```

Expected output:

```text
True
Severity.HIGH
```

### SSL/TLS Checks

`security_scanner/ssl_utils.py` extracts the hostname and port, opens a TLS connection,
loads the remote certificate with `cryptography`, and reads the certificate
expiry date.

The runner reports:

- HTTP target instead of HTTPS.
- SSL lookup failure.
- Expired certificate.
- Certificate expiring in 14 days or fewer.
- Valid certificate.

## Scoring

The score starts at `100`. Failed findings subtract points:

```text
Severity.HIGH     -20
Severity.MEDIUM   -10
Severity.LOW      -5
Severity.INFO      0
```

The score never goes below `0`.

This score is intentionally simple. It is useful for learning and quick
comparison, but it is not a professional risk rating.

## Serialization And Formatting

The scanner keeps internal data typed with dataclasses and enums. Before output,
`security_scanner/serializers.py` converts values into JSON-safe dictionaries.

Important conversion:

```text
Severity.HIGH -> "High"
Status.FAIL   -> "Fail"
datetime      -> ISO timestamp string
Finding       -> dict
ScanResult    -> dict
```

`security_scanner/formatters.py` then produces:

- Pretty JSON for automation and saved reports.
- A compact table for terminal use.

## Tests

Run all tests:

```bash
.venv/bin/python -B -m pytest
```

Coverage is configured in `pytest.ini`, so this command also runs coverage and
requires at least `70%` total coverage.

Run only exposure tests:

```bash
.venv/bin/python -B -m pytest tests/test_exposure_checks.py
```

Run type checks:

```bash
.venv/bin/python -B -m mypy security_scanner tests
```

Compile all Python files:

```bash
.venv/bin/python -B -m compileall -q security_scanner tests
```

Run Ruff if installed:

```bash
.venv/bin/python -B -m ruff check security_scanner tests
```

Run API app tests:

```bash
cd app
python -m pytest
```

Current tests cover:

- CLI help, URL validation, JSON output, table output, and file output.
- Header checks.
- Exposure checks.
- HTTP fetch helper behavior.
- URL fetcher behavior without live network calls.
- SSL utility parsing and error handling.
- Runner orchestration.
- Models, serializers, and formatters.
- `python -m security_scanner` entrypoint.
- Public package exports from `__init__.py` files.
- API health, scan, validation error, and empty scan history routes.

## Good Practices Used

### One Clear Package

The project uses one main package:

```text
security_scanner/
```

This avoids confusion from duplicate package names such as
`scanner`, `src/misconfig_scanner`, or old demo packages.

### Clear Boundaries

Each module has one main responsibility:

- `cli.py`: command-line interface only.
- `scanning/validators.py`: input validation only.
- `scanning/url_utils.py`: shared URL normalization and URL construction only.
- `scanning/runner.py`: orchestration only.
- `checks/security_headers.py`: header checks only.
- `checks/exposure.py`: exposure checks only.
- `scanning/url_fetcher.py` and `scanning/http_client.py`: HTTP fetching only.
- `core/models.py`: data structures only.
- `output/serializers.py`: conversion to JSON-safe data only.
- `output/formatters.py`: output formatting only.

This keeps the CLI from containing scanner logic and makes each part easier to
test.

### No Real Network In Unit Tests

Tests use fake fetchers, monkeypatching, and fake response objects. This keeps
the test suite:

- fast
- deterministic
- safe
- independent from external websites

### Typed Data

The project uses:

- dataclasses for structured results
- enums for severity levels
- strict mypy configuration
- typed function signatures

This catches mismatches such as:

```text
status vs passed
description vs message
check_name vs header
Severity.CRITICAL vs Severity.HIGH
```

### Dependency Hygiene

`requirements.txt` contains only dependencies needed by this project:

```text
cryptography
httpx
mypy
pytest
pytest-cov
ruff
```

It does not include unrelated packages from a full `pip freeze`, such as Flask,
Jinja, Celery, Redis, or SQLAlchemy.

### Safe HTTP Behavior

HTTP requests use:

- explicit timeouts
- redirects enabled where appropriate
- a scanner user agent
- error handling for request failures

Exposure path checks fetch only specific root-relative paths:

```text
/.env
/.git/config
```

### JSON-Safe Output

The internal code can use enums and datetimes. The output layer converts those
objects before JSON formatting, so saved reports contain normal strings and
booleans.

## Common Development Commands

Check status:

```bash
git status
```

Run tests:

```bash
.venv/bin/python -B -m pytest
```

Run API tests:

```bash
cd app
python -m pytest
```

Run type checks:

```bash
.venv/bin/python -B -m mypy security_scanner tests
```

Run one CLI command:

```bash
security-scanner --url https://example.com --format table
```

Save JSON:

```bash
security-scanner --url https://example.com --output result.json
```

## GitHub Push Commands

Use these commands to push to:

```text
https://github.com/attarehman962/security-misconfiguration-scanner
```

Check changes:

```bash
git status
```

Stage files:

```bash
git add README.md app .gitignore pyproject.toml requirements.txt security_scanner tests
```

Commit:

```bash
git commit -m "Update scanner workflow and exposure checks"
```

Add remote if needed:

```bash
git remote add origin https://github.com/attarehman962/security-misconfiguration-scanner.git
```

Update remote if it already exists:

```bash
git remote set-url origin https://github.com/attarehman962/security-misconfiguration-scanner.git
```

Push:

```bash
git push -u origin main
```

## Limitations

- This is not a replacement for professional penetration testing.
- Results depend on network access and server responses.
- Some sites block automated clients.
- Some findings are informational and need human review.
- The score is a simple educational score, not a compliance grade.

## Contribution Notes

Before contributing or pushing changes:

- Keep one clear package: `security_scanner`.
- Keep CLI logic in `cli.py` and scanner orchestration in `runner.py`.
- Keep API routes, schemas, and services inside `security_scanner/app/`.
- Add or update tests for behavior changes.
- Use fake responses and monkeypatching instead of real network calls in unit
  tests.
- Run `python -m pytest`, `python -m mypy security_scanner tests`, and the API
  tests from `app/` when touching the FastAPI service.
- Keep dependencies minimal.
- Do not commit virtual environments, caches, logs, coverage files, or generated
  reports.

## Safety Notes

Use this scanner only on systems where you have permission. Do not scan random
public targets, private systems, or third-party infrastructure without written
authorization.

The scanner sends HTTP requests to the target and selected root-relative paths
such as `/.env` and `/.git/config`. Treat scan output as sensitive because it
may reveal configuration mistakes, exposed metadata, or security weaknesses.
