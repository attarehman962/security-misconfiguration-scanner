# Security Misconfiguration Scanner

A Python command-line scanner for checking common web security
misconfigurations. The scanner fetches a target URL, checks response headers,
checks exposure risks, checks basic TLS certificate health, calculates a simple
score, and prints the result as a table or JSON.

This project is for learning, portfolio work, and authorized security testing.
Only scan systems that you own or have permission to test.

## Quick Start

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Run the scanner:

```bash
python -m scanner --url https://example.com --format table
```

Print JSON:

```bash
python -m scanner --url https://example.com --format json
```

Save JSON to a file:

```bash
python -m scanner --url https://example.com --output result.json
```

Show help:

```bash
python -m scanner --help
```

## What It Checks

The scanner currently checks one URL at a time and reports:

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

## Project Layout

```text
scanner/
  __init__.py          Public package exports
  __main__.py          Entry point for python -m scanner
  cli.py               argparse CLI, output selection, file saving
  runner.py            Main orchestration through run_full_scan()
  validators.py        CLI URL validation
  url_fetcher.py       Main target fetcher using httpx.Client
  http_client.py       Small safe fetch helper for extra exposure paths
  ssl_utils.py         TLS certificate expiry helpers
  headers.py           Security header checks
  checks/
    __init__.py        Checks package marker
    exposure.py        CORS, banner, directory, .env, and .git checks
  models.py            Severity, UrlScanResult, Finding, ScanResult
  serializers.py       Dataclass/enum to JSON-safe dictionaries
  formatters.py        JSON and terminal table formatting
  exceptions.py        Project exception types

tests/
  test_cli.py
  test_exposure_checks.py
  test_formatters.py
  test_header_checks.py
  test_http_client.py
  test_main.py
  test_models.py
  test_runner.py
  test_serializers.py
  test_ssl_utils.py
  test_url_fetcher.py
  test_validators.py
```

## Complete Workflow

```text
1. Terminal user
   python -m scanner --url https://example.com --format table

2. scanner/__main__.py
   Calls scanner.cli.main().

3. scanner/cli.py
   Builds argparse parser.
   Reads --url, --format, and --output.
   Calls validate_url() before scanning starts.
   Calls run_full_scan().

4. scanner/validators.py
   Rejects invalid URLs:
   - missing scheme
   - unsupported scheme
   - spaces
   - missing hostname
   - fragments such as #section

5. scanner/runner.py
   Coordinates the scan.
   Calls UrlFetcher().fetch(url).
   Adds header findings.
   Adds exposure findings.
   Adds SSL/TLS finding.
   Calculates total score.
   Returns ScanResult.

6. scanner/url_fetcher.py
   Fetches the main target.
   Captures final URL, status code, headers, body, SSL expiry, and errors.

7. scanner/headers.py
   Checks common browser security headers.

8. scanner/checks/exposure.py
   Checks CORS, server banners, X-Powered-By, directory listing, .env, and
   .git/config exposure.

9. scanner/http_client.py
   Performs safe small fetches for extra paths such as /.env and /.git/config.

10. scanner/ssl_utils.py
    Reads TLS certificate expiry for HTTPS targets.

11. scanner/models.py
    Stores all results as typed dataclasses and enums.

12. scanner/serializers.py
    Converts dataclasses and enums into JSON-safe dictionaries.

13. scanner/formatters.py
    Formats the result as JSON or a terminal table.

14. scanner/cli.py
    Prints output and optionally writes result.json.
```

Short flow:

```text
__main__.py
-> cli.py
-> validators.py
-> runner.py
-> url_fetcher.py
-> headers.py
-> checks/exposure.py
-> ssl_utils.py
-> models.py
-> serializers.py
-> formatters.py
-> terminal or JSON file
```

## CLI Details

Supported options:

```text
--url       Required target URL. Must start with http:// or https://.
--format    Output format. Choices: table, json. Default: table.
--output    Optional path to save JSON output.
```

Examples:

```bash
python -m scanner --url https://example.com
python -m scanner --url https://example.com --format table
python -m scanner --url https://example.com --format json
python -m scanner --url https://example.com --output result.json
```

Invalid format values are rejected by `argparse` before scanning:

```bash
python -m scanner --url https://example.com --format xml
```

Invalid URLs are rejected by `validate_url()` before network requests are made.

## Example Table Output

```text
Scan result for: https://example.com
Timestamp: 2026-06-08T12:00:00+00:00
Total score: 80

+---------------------------+--------+----------+-------------------------+
| Header                    | Passed | Severity | Message                 |
+---------------------------+--------+----------+-------------------------+
| Strict-Transport-Security | False  | High     | HSTS header is missing. |
+---------------------------+--------+----------+-------------------------+
```

## Example JSON Output

```json
{
  "findings": [
    {
      "category": "general",
      "header": "Content-Security-Policy",
      "message": "Missing Content-Security-Policy header.",
      "passed": false,
      "remediation": "Add Content-Security-Policy header.",
      "severity": "High"
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
from scanner.models import Severity

Severity.INFO
Severity.LOW
Severity.MEDIUM
Severity.HIGH
```

The enum prevents spelling mistakes in code. Serializers convert it to plain
JSON strings such as `"High"`.

### Finding

A `Finding` is one check result.

```python
from scanner.models import Finding, Severity

finding = Finding(
    header="Content-Security-Policy",
    passed=False,
    severity=Severity.HIGH,
    message="Missing Content-Security-Policy header.",
    remediation="Add a Content-Security-Policy header.",
)
```

Fields:

- `header`: Name of the header or check.
- `passed`: `True` if the check passed, `False` if it failed.
- `severity`: `Severity.INFO`, `LOW`, `MEDIUM`, or `HIGH`.
- `message`: Human-readable result.
- `remediation`: Suggested fix.
- `category`: Defaults to `"general"`.

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

`FetchResult` in `scanner/http_client.py` is a smaller safe fetch result used
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

from scanner.models import ScanResult

result = ScanResult(
    url="https://example.com",
    timestamp=datetime.now(timezone.utc),
    total_score=80,
    findings=[finding],
)
```

## Checks

### Security Header Checks

`scanner/headers.py` checks:

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
from scanner.headers import findings_to_json, run_header_checks

headers = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Frame-Options": "DENY",
}

findings = run_header_checks(headers)
print(findings_to_json(findings))
PY
```

### Exposure Checks

`scanner/checks/exposure.py` checks:

- Weak wildcard CORS on non-public APIs.
- Server header version exposure.
- `X-Powered-By` framework/runtime exposure.
- Parent directory listing markers in the body.
- Public `/.env`.
- Public `/.git/config`.

Example:

```bash
python - <<'PY'
from scanner.checks.exposure import check_weak_cors

finding = check_weak_cors({"Access-Control-Allow-Origin": "*"})
print(finding.passed)
print(finding.severity)
PY
```

Expected output:

```text
False
Severity.HIGH
```

Example for `/.env`:

```bash
python - <<'PY'
from collections.abc import Mapping
from dataclasses import dataclass

from scanner.checks.exposure import check_exposed_env


@dataclass
class FakeResponse:
    status_code: int
    headers: Mapping[str, str]
    body: str


def fake_fetcher(url: str, timeout: int) -> FakeResponse:
    return FakeResponse(status_code=200, headers={}, body="SECRET_KEY=test")


finding = check_exposed_env("https://example.com", fake_fetcher)
print(finding.passed)
print(finding.severity)
PY
```

Expected output:

```text
False
Severity.HIGH
```

### SSL/TLS Checks

`scanner/ssl_utils.py` extracts the hostname and port, opens a TLS connection,
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
`scanner/serializers.py` converts values into JSON-safe dictionaries.

Important conversion:

```text
Severity.HIGH -> "High"
datetime      -> ISO timestamp string
Finding       -> dict
ScanResult    -> dict
```

`scanner/formatters.py` then produces:

- Pretty JSON for automation and saved reports.
- A compact table for terminal use.

## Testing

Run all tests:

```bash
.venv/bin/python -B -m pytest
```

Run only exposure tests:

```bash
.venv/bin/python -B -m pytest tests/test_exposure_checks.py
```

Run type checks:

```bash
.venv/bin/python -B -m mypy scanner tests
```

Compile all Python files:

```bash
.venv/bin/python -B -m compileall -q scanner tests
```

Run Ruff if installed:

```bash
.venv/bin/python -B -m ruff check scanner tests
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
- `python -m scanner` entrypoint.

## Good Practices Used

### One Clear Package

The project uses one main package:

```text
scanner/
```

This avoids confusion from duplicate package names such as
`security_scanner`, `scanner`, or old demo packages.

### Clear Boundaries

Each module has one main responsibility:

- `cli.py`: command-line interface only.
- `validators.py`: input validation only.
- `runner.py`: orchestration only.
- `headers.py`: header checks only.
- `checks/exposure.py`: exposure checks only.
- `url_fetcher.py` and `http_client.py`: HTTP fetching only.
- `models.py`: data structures only.
- `serializers.py`: conversion to JSON-safe data only.
- `formatters.py`: output formatting only.

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

Run type checks:

```bash
.venv/bin/python -B -m mypy scanner tests
```

Run one CLI command:

```bash
.venv/bin/python -m scanner --url https://example.com --format table
```

Save JSON:

```bash
.venv/bin/python -m scanner --url https://example.com --output result.json
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
git add README.md pyproject.toml requirements.txt scanner tests .gitignore
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

## Responsible Use

Use this scanner only on systems where you have permission. Do not scan random
public targets, private systems, or third-party infrastructure without written
authorization.
