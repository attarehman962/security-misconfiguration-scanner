# Security Misconfiguration Scanner

A Python command-line scanner that checks a web target for common security
misconfigurations. It fetches the target URL, inspects response headers, checks
basic TLS certificate health, calculates a simple score, and prints the result
as a terminal table or JSON.

This project is intended for learning, portfolio work, and authorized security
testing only. Only scan systems that you own or have permission to test.

## What This Project Does

The scanner currently checks one target URL at a time and reports:

- Whether the URL can be fetched.
- The final URL after redirects.
- Missing or present browser security headers.
- Whether the target uses HTTPS.
- Whether the SSL/TLS certificate can be inspected.
- Whether the SSL/TLS certificate is expired or close to expiry.
- A simple security score from `0` to `100`.
- Structured findings with severity, message, and remediation.

## Main Command

```bash
python -m scanner --url https://example.com --format table
```

You can also output JSON:

```bash
python -m scanner --url https://example.com --format json
```

Save the JSON report to a file:

```bash
python -m scanner --url https://example.com --format table --output result.json
```

## Project Structure

```text
scanner/
  __init__.py       Package marker
  __main__.py       Allows running: python -m scanner
  cli.py            CLI parser, output selection, and report saving
  runner.py         Main scan pipeline through run_full_scan()
  url_fetcher.py    Fetches URL metadata with httpx
  ssl_utils.py      Reads remote SSL/TLS certificate expiry
  headers.py        Runs security header checks
  models.py         Dataclasses for UrlScanResult, Finding, and ScanResult
  serializers.py    Converts dataclasses into JSON-safe dictionaries
  formatters.py     Formats ScanResult as JSON or a terminal table
  validators.py     Validates command-line URLs
  exceptions.py     Project exception types

tests/
  test_cli.py
  test_formatters.py
  test_header_checks.py
  test_main.py
  test_models.py
  test_runner.py
  test_serializers.py
  test_ssl_utils.py
  test_url_fetcher.py
  test_validators.py
```

## How The Scanner Works

```text
Terminal user
    |
    | python -m scanner --url https://example.com --format table
    v
scanner/cli.py
    Parses arguments, validates the URL, chooses output format
    |
    v
scanner/runner.py
    run_full_scan(url)
    |
    |----------------------------|-----------------------------|
    v                            v                             v
scanner/url_fetcher.py       scanner/ssl_utils.py          scanner/headers.py
Fetch URL and headers        Check TLS certificate          Check headers
    |                            |                             |
    |----------------------------|-----------------------------|
                                 v
scanner/models.py
    Build ScanResult with list[Finding]
    |
    v
scanner/serializers.py
    Convert dataclasses to dictionaries
    |
    |----------------------------|
    v                            v
scanner/formatters.py        scanner/formatters.py
JSON output                  Table output
```

## Requirements

- Python `3.14` or newer
- `httpx`
- `cryptography`
- `pytest`, `mypy`, and `ruff` for development checks

The required runtime packages are listed in `requirements.txt` and
`pyproject.toml`.

## Installation

Create a virtual environment:

```bash
python3 -m venv .venv
```

Activate it on Linux or macOS:

```bash
source .venv/bin/activate
```

Install the project dependencies:

```bash
python -m pip install -r requirements.txt
```

For editable development installation:

```bash
python -m pip install -e .
```

If you want the development dependencies from `pyproject.toml`:

```bash
python -m pip install -e ".[dev]"
```

## CLI Usage

Show help:

```bash
python -m scanner --help
```

Run a scan in table format:

```bash
python -m scanner --url https://example.com --format table
```

Run a scan in JSON format:

```bash
python -m scanner --url https://example.com --format json
```

Save a JSON report:

```bash
python -m scanner --url https://example.com --output result.json
```

The scanner accepts `http://` and `https://` URLs. The CLI rejects empty URLs,
unsupported schemes, URLs with spaces, missing hostnames, and fragment-only
targets such as `#section`.

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

## Security Header Checks

The scanner checks these response headers:

- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`

Header names are checked case-insensitively because real HTTP response headers
can arrive in different letter casing.

You can run the header checks directly:

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

The `headers` value is a Python dictionary where each key is a header name and
each value is the header value:

```python
{
    "Header-Name": "header value"
}
```

## Data Models

### Finding

A `Finding` represents one check result.

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
- `passed`: `True` when the check passed, `False` when it failed.
- `severity`: One of `Severity.LOW`, `Severity.MEDIUM`, or `Severity.HIGH`.
- `message`: Human-readable result message.
- `remediation`: Suggested fix.
- `category`: Defaults to `"general"`.

### ScanResult

A `ScanResult` represents the complete scan for one URL.

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

Fields:

- `url`: Final scanned URL.
- `timestamp`: When the scan result was created.
- `total_score`: Security score from `0` to `100`.
- `findings`: List of `Finding` objects.

## Formatters

Use `format_json()` when you want machine-readable output:

```python
from scanner.formatters import format_json

print(format_json(result))
```

Use `format_table()` when you want terminal output:

```python
from scanner.formatters import format_table

print(format_table(result))
```

## Development Checks

Run the full test suite:

```bash
.venv/bin/python -B -m pytest
```

Run type checks:

```bash
.venv/bin/python -B -m mypy scanner tests
```

Compile all Python files:

```bash
.venv/bin/python -B -m compileall -q scanner tests
```

Run Ruff if it is installed:

```bash
.venv/bin/python -B -m ruff check scanner tests
```

## Current Test Coverage

The test suite covers:

- CLI JSON output, table output, and file writing.
- CLI help output, invalid URL rejection, and invalid format rejection.
- CLI argument validation before scanner execution.
- JSON and table formatters.
- Header checks for passing, failing, partial, and case-insensitive headers.
- Main runner behavior for successful scans, fetch errors, SSL findings, and scoring.
- URL fetching behavior without live network calls.
- SSL utility parsing and handled socket/DNS errors.
- Model helper methods and JSON-safe dictionaries.
- `python -m scanner` entrypoint behavior.
- Serializer output for `Finding` and `ScanResult`.
- URL validation for valid URLs, missing schemes, unsupported schemes, and spaces.

## GitHub Push Commands

Use these commands to commit and push this project to:

```text
https://github.com/attarehman962/security-misconfiguration-scanner
```

Check what changed:

```bash
git status
```

Stage the project files:

```bash
git add README.md pyproject.toml requirements.txt scanner tests .gitignore
```

Create a commit:

```bash
git commit -m "Merge scanner package and update tests"
```

Add the GitHub remote if it does not already exist:

```bash
git remote add origin https://github.com/attarehman962/security-misconfiguration-scanner.git
```

If the remote already exists, update it:

```bash
git remote set-url origin https://github.com/attarehman962/security-misconfiguration-scanner.git
```

Push to GitHub:

```bash
git push -u origin main
```

## Notes

- This is not a replacement for professional security testing.
- Results depend on network access and the target server response.
- Some websites block automated clients, redirects, or TLS inspection.
- Only use this scanner on targets you are allowed to test.
