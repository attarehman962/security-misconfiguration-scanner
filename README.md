Security Misconfiguration Scanner
=================================

This is a Python security portfolio project. It checks basic web security
configuration signals for one URL or many URLs. The goal is to show that I can
build a small command-line security tool with clean models, network fetching,
SSL inspection, batch processing, and type checking.

This project is for learning, portfolio, and authorized testing only. Do not
scan systems you do not own or do not have permission to test.

What I Am Doing In This Project
-------------------------------

I am building a simple scanner that helps identify common security
misconfigurations on websites. The scanner does not exploit anything. It only
collects public metadata and reports whether the target looks safe or risky in
basic areas.

The project currently checks:

- Whether a URL is reachable.
- What final URL is reached after redirects.
- What HTTP status code is returned.
- What response headers are returned.
- Whether an HTTPS certificate has an expiry date.
- Whether the SSL certificate is expired, expiring soon, healthy, or unknown.
- Whether important security headers are missing.
- Whether a target uses insecure HTTP instead of HTTPS.
- Multiple URLs from a file without crashing the whole run if one URL fails.

Main Idea
---------

The project is split into small tools:

- `main.py` fetches metadata for one URL.
- `batch_scan.py` scans many URLs from `urls.txt`.
- `ssl_classifier.py` checks SSL certificate expiry risk.
- `security_headers.py` checks for important HTTP security headers.
- `src/misconfig_scanner/demo.py` runs the core domain model demo and prints a
  JSON report.

The lower-level scanner package contains reusable code:

- `scanner/url_fetcher.py` handles URL fetching with `httpx`.
- `scanner/ssl_utils.py` handles SSL certificate expiry lookup.
- `scanner/models.py` defines the URL scan result model.

The `src/misconfig_scanner/` package contains the portfolio-style domain
models:

- `Finding`
- `Report`
- `Scanner`
- `RiskScore`

These models are used to show how findings can be validated, serialized to
JSON, counted by severity, and used for a simple security gate.

Features
--------

- Single URL scanning.
- Batch URL scanning.
- SSL expiry classification.
- Security header checking.
- JSON report generation.
- Basic severity scoring.
- Type hints and mypy support.
- Simple command-line interface.
- Safe error handling for failed URLs.

Requirements
------------

- Python 3.14+
- `httpx`
- `cryptography`
- `mypy` for type checking
- `pytest` is configured, but there are no tests yet

Setup
-----

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies from `requirements.txt`:

```bash
python -m pip install -r requirements.txt
```

Or install the project from `pyproject.toml`:

```bash
python -m pip install -e .
```

Important: use the virtual environment before running the scanner. On this
machine, `httpx` is installed in `.venv`, not necessarily in the system Python.

```bash
source .venv/bin/activate
```

How To Run
----------

### 1. Fetch one URL

Use `main.py` to fetch the URL, final redirected URL, status code, SSL expiry,
and response headers.

```bash
python main.py https://example.com
```

Example output shape:

```text
Input URL: https://example.com
Final URL: https://example.com
Status Code: 200
SSL Expiry UTC: 2026-01-01T00:00:00+00:00
Successful: True

Response Headers:
content-type: text/html
...
```

### 2. Scan many URLs

Use `batch_scan.py` with a URL list file:

```bash
python batch_scan.py urls.txt
```

The batch scanner reads one URL per line and prints a table.

Example `urls.txt`:

```text
https://example.com
http://example.com
https://google.com
https://expired.badssl.com
```

Blank lines are skipped. Lines that start with `#` are treated as comments.

### 3. Check SSL expiry risk

Use `ssl_classifier.py` to classify the SSL certificate status:

```bash
python ssl_classifier.py https://example.com
```

Possible SSL statuses:

- `HEALTHY`: certificate is valid and not close to expiry.
- `EXPIRING_SOON`: certificate expires within 30 days.
- `EXPIRED`: certificate expiry date is already in the past.
- `UNKNOWN`: expiry could not be fetched, or the target is not HTTPS.

### 4. Check security headers

Use `security_headers.py` to check common security headers:

```bash
python security_headers.py https://example.com
```

Headers checked:

- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`

Missing headers do not always mean a site is vulnerable, but they are useful
signals for common hardening gaps.

### 5. Run the core model demo

Use the package demo to generate a JSON report:

```bash
PYTHONPATH=src python -m misconfig_scanner.demo
```

This demo creates a scanner for `http://example.com`, detects insecure HTTP,
and prints a JSON report with:

- scanner name
- target
- generated timestamp
- metadata
- severity counts
- security gate result
- findings

Project Flow
------------

The scanner flow is:

1. User provides a URL.
2. The URL is normalized if needed.
3. The scanner fetches the URL with redirects enabled.
4. The scanner collects status code, final URL, and headers.
5. If HTTPS is used, the scanner tries to fetch SSL certificate expiry.
6. Errors are stored in the result instead of crashing the whole run.
7. Batch mode repeats this for every URL in the file.
8. Reports summarize findings and severity counts.

File-by-File Explanation
------------------------

`main.py`

Runs a single URL scan from the command line. It prints the input URL, final
URL, status code, SSL expiry, success status, and response headers.

`batch_scan.py`

Reads URLs from a text file and scans them one by one. If one URL fails, the
program records the error and continues scanning the next URL.

`ssl_classifier.py`

Fetches the SSL certificate expiry date and classifies the risk. This is useful
for finding certificates that are expired or close to expiry.

`security_headers.py`

Fetches a URL and checks whether common hardening headers are present.

`scanner/url_fetcher.py`

Contains `UrlFetcher`, the reusable class that performs HTTP requests using
`httpx`.

`scanner/ssl_utils.py`

Contains SSL helper functions for extracting hostname and port and fetching
certificate expiry dates.

`scanner/models.py`

Contains `UrlScanResult`, the data object returned by the URL fetcher.

`src/misconfig_scanner/models.py`

Contains the core domain objects for a structured security report:

- `Severity`
- `Finding`
- `Report`
- `Scanner`
- `RiskScore`

`src/misconfig_scanner/scanner.py`

Provides a compatibility scanner interface used by `batch_scan.py`.

`urls.txt`

Example input file for batch scanning.

Development Checks
------------------

Compile all Python files:

```bash
python -m compileall src scanner main.py batch_scan.py ssl_classifier.py security_headers.py
```

Run mypy on the main scanner code:

```bash
mypy --explicit-package-bases scanner main.py batch_scan.py src/misconfig_scanner
```

Run mypy on the SSL classifier:

```bash
mypy ssl_classifier.py
```

Run pytest:

```bash
pytest
```

Note: pytest is configured, but this project does not have test files yet.

What This Project Shows
-----------------------

This project demonstrates:

- Python command-line tooling.
- HTTP request handling with `httpx`.
- SSL certificate inspection.
- Security header analysis.
- Data modeling with dataclasses.
- JSON-compatible report generation.
- Error handling for network tools.
- Type hints and mypy checking.
- Basic project packaging with `pyproject.toml`.

Limitations
-----------

This is a beginner-friendly scanner. It does not perform deep vulnerability
testing. It does not attempt exploitation. It does not replace professional
security tools.

Current limitations:

- No automated test suite yet.
- No HTML report output yet.
- No database or scan history.
- No advanced vulnerability checks.
- Some network results depend on DNS, firewall, TLS, and remote server behavior.

Future Improvements
-------------------

Possible next steps:

- Add pytest tests.
- Add JSON and CSV output for batch scans.
- Add HTML report generation.
- Add more security checks.
- Add better URL validation.
- Add logging.
- Add GitHub Actions for mypy and tests.
- Add a single unified CLI entry point.

Git Notes
---------

Generated files should not be committed. The `.gitignore` excludes:

- Python bytecode and `__pycache__`
- virtual environments
- build outputs
- mypy, pytest, and ruff caches
- local `.env` files
- local editor files
- local output folders

Before pushing, check:

```bash
git status
```

Then commit the useful source files:

```bash
git add .
git commit -m "Update security scanner documentation"
```
