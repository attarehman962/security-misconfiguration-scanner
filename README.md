Security Misconfiguration Scanner
=================================

A Python command-line security scanner for basic web misconfiguration checks.

The project is now merged into one main package:

```text
scanner/
```

The supported command is:

```bash
python -m scanner --url https://example.com --format table
```

This project is for learning, portfolio work, and authorized testing only. Do
not scan systems you do not own or do not have permission to test.

What This Project Does
----------------------

The scanner checks one target URL and reports:

- whether the URL can be fetched
- the final URL after redirects
- common missing security headers
- whether the target uses HTTPS
- whether the SSL certificate can be inspected
- whether the SSL certificate is expired or close to expiry
- a simple total security score
- structured findings in table or JSON format

Current Architecture
--------------------

```text
Terminal user
    |
    | python -m scanner --url https://example.com --format table
    v
scanner/cli.py
    argparse + output handling
    |
    | validated URL
    v
scanner/runner.py
    run_full_scan()
    |
    |----------------------------|-----------------------------|
    v                            v                             v
scanner/url_fetcher.py       scanner/ssl_utils.py          scanner/headers.py
fetches URL + headers        checks SSL expiry             runs header checks
    |                            |                             |
    |----------------------------|-----------------------------|
                                 v
scanner/models.py
    ScanResult + list[Finding]
    |
    v
scanner/serializers.py
    dataclasses -> dictionaries
    |
    |----------------------------|
    v                            v
scanner/formatters.py        scanner/formatters.py
JSON output                  table output
```

Project Layout
--------------

```text
scanner/
  __main__.py       Runs the CLI when using python -m scanner
  cli.py            Parses command-line args and handles output
  runner.py         Coordinates the full scan
  url_fetcher.py    Fetches the URL with httpx
  ssl_utils.py      Reads SSL certificate expiry
  headers.py        Checks required security headers
  models.py         UrlScanResult, Finding, ScanResult, Severity
  serializers.py    Converts results to JSON-safe dictionaries
  formatters.py     Formats output as JSON or table
  validators.py     Validates CLI URLs
  exceptions.py     Scanner exception types

tests/
  test_cli.py
  test_formatters.py
  test_header_checks.py
  test_validators.py
```

Removed Old/Duplicate Files
---------------------------

The project used to have several separate demo scripts and duplicate packages.
Those have been removed so the codebase has one clear path:

```text
python -m scanner
```

Removed duplicate/old surfaces:

- `main.py`
- `batch_scan.py`
- `ssl_classifier.py`
- `security_headers.py`
- `security_scanner/`
- `src/misconfig_scanner/`
- `urls.txt`

Installation
------------

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Or install the package in editable mode:

```bash
python -m pip install -e .
```

Usage
-----

Run a scan and print a table:

```bash
python -m scanner --url https://example.com --format table
```

Run a scan and print JSON:

```bash
python -m scanner --url https://example.com --format json
```

Run a scan, print a table, and save JSON to a file:

```bash
python -m scanner --url https://example.com --format table --output result.json
```

Show CLI help:

```bash
python -m scanner --help
```

Output Formats
--------------

Table output is meant for terminal reading:

```text
Scan result for: https://example.com
Timestamp: 2026-06-07T12:00:00+00:00
Total score: 80

+---------------------------+--------+----------+-------------------------+
| Header                    | Passed | Severity | Message                 |
+---------------------------+--------+----------+-------------------------+
| Strict-Transport-Security | False  | High     | HSTS header is missing. |
+---------------------------+--------+----------+-------------------------+
```

JSON output is meant for saving, scripting, or later report generation:

```json
{
  "findings": [],
  "timestamp": "2026-06-07T12:00:00+00:00",
  "total_score": 100,
  "url": "https://example.com"
}
```

Data Model
----------

`Finding` represents one check result:

```python
Finding(
    header="Content-Security-Policy",
    passed=False,
    severity="High",
    message="Missing Content-Security-Policy header.",
    remediation="Add Content-Security-Policy header.",
)
```

`ScanResult` represents the whole scan for one URL:

```python
ScanResult(
    url="https://example.com",
    timestamp=...,
    total_score=80,
    findings=[finding],
)
```

Security Header Checks
----------------------

`scanner/headers.py` checks these headers:

- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`

You can also run header checks directly in Python:

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

Development Checks
------------------

Compile all Python files:

```bash
python -m compileall scanner tests
```

Run mypy:

```bash
mypy scanner tests
```

Run tests:

```bash
pytest
```

Expected result:

```text
10 passed
```

Notes
-----

- Network results depend on DNS, TLS, firewall, and the remote server.
- If a fetch fails, the scanner returns a failed finding instead of crashing.
- The score starts at 100 and subtracts penalties for failed findings.
- This is a beginner-friendly scanner, not a replacement for professional
  vulnerability scanners.
