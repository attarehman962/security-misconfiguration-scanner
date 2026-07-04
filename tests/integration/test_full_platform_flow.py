from __future__ import annotations

import asyncio
import csv
import io
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any, Iterable

import httpx
import pytest
from pypdf import PdfReader


@dataclass(frozen=True)
class ApiEndpoints:
    """Centralizes API paths used by the full integration test."""

    health: str = "/health"
    register: str = "/api/v1/auth/register"
    login: str = "/api/v1/auth/login"
    create_scan: str = "/api/v1/scans"
    create_scrape_job: str = "/api/v1/scrape/jobs"

    def scan_detail(self, scan_id: str) -> str:
        """Return the scan detail endpoint for a scan identifier."""
        return f"/api/v1/scans/{scan_id}"

    def scan_report_pdf(self, scan_id: str) -> str:
        """Return the PDF report endpoint for a scan identifier."""
        return f"/api/v1/scans/{scan_id}/report.pdf"

    def scrape_job_detail(self, job_id: str) -> str:
        """Return the scraping job detail endpoint for a job identifier."""
        return f"/api/v1/scrape/jobs/{job_id}"

    def scrape_job_csv_export(self, job_id: str) -> str:
        """Return the CSV export endpoint for a scraping job identifier."""
        return f"/api/v1/scrape/jobs/{job_id}/export.csv"


SUCCESS_STATUSES = {"completed", "complete", "success", "finished", "done"}
FAILURE_STATUSES = {"failed", "failure", "error", "cancelled", "canceled"}


def get_required_env(name: str, default: str | None = None) -> str:
    """Read an environment variable or return a provided default."""
    value = os.getenv(name, default)
    if value is None or value.strip() == "":
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def extract_identifier(response_payload: dict[str, Any], keys: Iterable[str]) -> str:
    """Extract a resource identifier from a response payload."""
    for key in keys:
        value = response_payload.get(key)
        if value is not None and str(value).strip():
            return str(value)

    available_keys = ", ".join(sorted(response_payload.keys()))
    expected_keys = ", ".join(keys)
    raise AssertionError(
        f"Response did not contain identifier. "
        f"Expected one of: {expected_keys}. "
        f"Available keys: {available_keys}"
    )


def extract_status(response_payload: dict[str, Any]) -> str:
    """Extract and normalize a resource status from a response payload."""
    raw_status = response_payload.get("status") or response_payload.get("state")
    if raw_status is None:
        raise AssertionError(f"Response has no status/state field: {response_payload}")
    return str(raw_status).strip().lower()


async def wait_for_api_health(
    client: httpx.AsyncClient,
    health_path: str,
    timeout_seconds: float = 60.0,
) -> None:
    """Wait until the API health endpoint responds successfully."""
    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None

    while time.monotonic() < deadline:
        try:
            response = await client.get(health_path)
            if response.status_code == 200:
                return
            last_error = RuntimeError(
                f"Health check returned HTTP {response.status_code}: "
                f"{response.text[:300]}"
            )
        except (
            httpx.ConnectError,
            httpx.ReadTimeout,
            httpx.RemoteProtocolError,
        ) as error:
            last_error = error

        await asyncio.sleep(1.0)

    raise TimeoutError(f"API did not become healthy: {last_error!r}")


async def poll_until_completed(
    client: httpx.AsyncClient,
    status_path: str,
    token: str,
    timeout_seconds: float = 90.0,
    interval_seconds: float = 2.0,
) -> dict[str, Any]:
    """Poll a status endpoint until the resource completes or fails."""
    deadline = time.monotonic() + timeout_seconds
    headers = {"Authorization": f"Bearer {token}"}

    while time.monotonic() < deadline:
        response = await client.get(status_path, headers=headers)
        assert response.status_code == 200, response.text

        payload = response.json()
        current_status = extract_status(payload)

        if current_status in SUCCESS_STATUSES:
            return payload

        if current_status in FAILURE_STATUSES:
            raise AssertionError(
                f"Resource failed at {status_path}. Payload: {payload}"
            )

        await asyncio.sleep(interval_seconds)

    raise TimeoutError(f"Resource did not complete in time: {status_path}")


def assert_pdf_contains_findings(
    pdf_bytes: bytes,
    expected_terms: Iterable[str],
    minimum_size_bytes: int = 800,
) -> None:
    """Assert that a PDF is non-empty and contains expected finding text."""
    assert len(pdf_bytes) >= minimum_size_bytes, (
        f"PDF too small. Got {len(pdf_bytes)} bytes."
    )

    reader = PdfReader(io.BytesIO(pdf_bytes))
    extracted_text_parts = [
        page.extract_text() or ""
        for page in reader.pages
    ]
    extracted_text = "\n".join(extracted_text_parts)

    assert extracted_text.strip(), "PDF text extraction returned no content."

    missing_terms = [
        term
        for term in expected_terms
        if term.lower() not in extracted_text.lower()
    ]
    assert not missing_terms, (
        f"PDF missing expected terms: {missing_terms}. "
        f"Extracted text preview: {extracted_text[:500]}"
    )


def assert_csv_has_rows(csv_text: str) -> None:
    """Assert that exported CSV text contains at least one data row."""
    csv_reader = csv.DictReader(io.StringIO(csv_text))
    rows = list(csv_reader)

    assert csv_reader.fieldnames, "CSV has no header row."
    assert rows, "CSV has headers but no data rows."

    non_empty_rows = [
        row for row in rows
        if any(str(value).strip() for value in row.values() if value is not None)
    ]
    assert non_empty_rows, "CSV rows are present but all values are empty."
    
@pytest.mark.integration
@pytest.mark.slow
async def test_full_authenticated_scan_report_and_scrape_flow() -> None:
    """Run the complete authenticated scanner and scraper platform flow."""
    endpoints = ApiEndpoints()

    base_url = get_required_env("BASE_URL", "http://127.0.0.1:8000")
    target_scan_url = get_required_env(
        "TARGET_SCAN_URL",
        "http://target-site",
    )

    timeout = httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=10.0)

    async with httpx.AsyncClient(
        base_url=base_url,
        timeout=timeout,
        follow_redirects=True,
    ) as client:
        await wait_for_api_health(client, endpoints.health)

        unique_suffix = uuid.uuid4().hex
        email = f"atta.day21.{unique_suffix}@example.test"
        password = "StrongPassword123!"

        register_response = await client.post(
            endpoints.register,
            json={
                "email": email,
                "password": password,
                "full_name": "Atta Day 21",
            },
        )
        assert register_response.status_code in {200, 201}, (
            register_response.text
        )

        login_response = await client.post(
            endpoints.login,
            json={
                "email": email,
                "password": password,
            },
        )
        assert login_response.status_code == 200, login_response.text

        login_payload = login_response.json()
        access_token = login_payload.get("access_token")
        assert isinstance(access_token, str) and access_token.strip(), (
            f"Login response missing access_token: {login_payload}"
        )

        auth_headers = {"Authorization": f"Bearer {access_token}"}

        create_scan_response = await client.post(
            endpoints.create_scan,
            headers=auth_headers,
            json={
                "target_url": target_scan_url,
            },
        )
        assert create_scan_response.status_code in {200, 201, 202}, (
            create_scan_response.text
        )

        scan_payload = create_scan_response.json()
        scan_id = extract_identifier(scan_payload, ("id", "scan_id"))

        completed_scan = await poll_until_completed(
            client=client,
            status_path=endpoints.scan_detail(scan_id),
            token=access_token,
        )

        assert extract_status(completed_scan) in SUCCESS_STATUSES

        report_response = await client.get(
            endpoints.scan_report_pdf(scan_id),
            headers=auth_headers,
        )
        assert report_response.status_code == 200, report_response.text

        content_type = report_response.headers.get("content-type", "")
        assert "application/pdf" in content_type.lower(), (
            f"Unexpected report content type: {content_type}"
        )

        assert_pdf_contains_findings(
            pdf_bytes=report_response.content,
            expected_terms=[
                "severity",
                "finding",
            ],
        )

        create_scrape_response = await client.post(
            endpoints.create_scrape_job,
            headers=auth_headers,
            json={
                "target_url": target_scan_url,
                "selectors": {
                    "links": "a",
                    "headings": "h1",
                    "table_rows": "tr",
                },
            },
        )
        assert create_scrape_response.status_code in {200, 201, 202}, (
            create_scrape_response.text
        )

        scrape_payload = create_scrape_response.json()
        scrape_job_id = extract_identifier(
            scrape_payload,
            ("id", "job_id", "scrape_job_id"),
        )

        completed_scrape_job = await poll_until_completed(
            client=client,
            status_path=endpoints.scrape_job_detail(scrape_job_id),
            token=access_token,
        )

        assert extract_status(completed_scrape_job) in SUCCESS_STATUSES

        csv_response = await client.get(
            endpoints.scrape_job_csv_export(scrape_job_id),
            headers=auth_headers,
        )
        assert csv_response.status_code == 200, csv_response.text

        csv_content_type = csv_response.headers.get("content-type", "")
        assert (
            "text/csv" in csv_content_type.lower()
            or "application/octet-stream" in csv_content_type.lower()
        ), f"Unexpected CSV content type: {csv_content_type}"

        assert_csv_has_rows(csv_response.text)