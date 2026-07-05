from __future__ import annotations

import asyncio
import csv
import io
import os
import time
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

import httpx
import pytest
from pypdf import PdfReader


@dataclass(frozen=True)
class ApiEndpoints:
    """Centralizes API paths used by the full integration test."""

    health: str = "/api/v1/health"
    register: str = "/api/v1/auth/register"
    login: str = "/api/v1/auth/login"
    me: str = "/api/v1/auth/me"
    create_scan: str = "/api/v1/scans"
    scrape_url: str = "/api/v1/scrape/"
    save_scrape_results: str = "/api/v1/scrape/results"
    scrape_results_csv_export: str = "/api/v1/scrape/results/export"

    def scan_detail(self, scan_id: str) -> str:
        """Return the scan detail endpoint for a scan identifier."""
        return f"/api/v1/scans/{scan_id}"

    def scan_report_pdf(self, scan_id: str) -> str:
        """Return the PDF report endpoint for a scan identifier."""
        return f"/api/v1/scans/{scan_id}/report"


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


def response_preview(response: httpx.Response, max_chars: int = 500) -> str:
    """Return a compact response preview for assertion messages."""
    content_type = response.headers.get("content-type", "<missing>")
    text = response.text.replace("\n", "\\n")
    return (
        f"HTTP {response.status_code}, content-type={content_type}, "
        f"body={text[:max_chars]}"
    )


def assert_status(
    response: httpx.Response,
    expected_statuses: set[int],
    context: str,
) -> None:
    """Assert an HTTP response status with useful failure context."""
    assert response.status_code in expected_statuses, (
        f"{context} returned unexpected status. "
        f"Expected {sorted(expected_statuses)}. {response_preview(response)}"
    )


def assert_json_object(response: httpx.Response, context: str) -> dict[str, Any]:
    """Return a JSON object response or fail with content diagnostics."""
    content_type = response.headers.get("content-type", "")
    assert "application/json" in content_type.lower(), (
        f"{context} did not return JSON. {response_preview(response)}"
    )

    try:
        payload = response.json()
    except ValueError as error:
        raise AssertionError(
            f"{context} returned invalid JSON. {response_preview(response)}"
        ) from error

    assert isinstance(payload, dict), (
        f"{context} returned JSON {type(payload).__name__}, expected object: {payload}"
    )
    return payload


def assert_json_array(response: httpx.Response, context: str) -> list[Any]:
    """Return a JSON array response or fail with content diagnostics."""
    content_type = response.headers.get("content-type", "")
    assert "application/json" in content_type.lower(), (
        f"{context} did not return JSON. {response_preview(response)}"
    )

    try:
        payload = response.json()
    except ValueError as error:
        raise AssertionError(
            f"{context} returned invalid JSON. {response_preview(response)}"
        ) from error

    assert isinstance(payload, list), (
        f"{context} returned JSON {type(payload).__name__}, expected array: {payload}"
    )
    return payload


def assert_bearer_access_token(login_payload: dict[str, Any]) -> str:
    """Validate the login token response and return the access token."""
    access_token = login_payload.get("access_token")
    assert isinstance(access_token, str) and access_token.strip(), (
        f"Login response missing access_token: {login_payload}"
    )

    token_type = login_payload.get("token_type")
    assert str(token_type).lower() == "bearer", (
        f"Login response has wrong token_type: {login_payload}"
    )

    token_parts = access_token.split(".")
    assert len(token_parts) == 3 and all(token_parts), (
        "Login response access_token is not a compact JWT with three "
        f"non-empty sections: {access_token!r}"
    )

    return access_token


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
        except httpx.RequestError as error:
            last_error = error

        await asyncio.sleep(1.0)

    raise TimeoutError(
        f"API at {client.base_url} did not become healthy via {health_path}: "
        f"{last_error!r}"
    )


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
    last_payload: dict[str, Any] | None = None
    last_error: str | None = None

    while time.monotonic() < deadline:
        response = await client.get(status_path, headers=headers)
        if response.status_code != 200:
            last_error = response_preview(response)
            await asyncio.sleep(interval_seconds)
            continue

        payload = assert_json_object(response, f"Polling {status_path}")
        last_payload = payload
        current_status = extract_status(payload)

        if current_status in SUCCESS_STATUSES:
            return payload

        if current_status in FAILURE_STATUSES:
            raise AssertionError(
                f"Resource failed at {status_path} with status "
                f"{current_status!r}. Payload: {payload}"
            )

        await asyncio.sleep(interval_seconds)

    raise TimeoutError(
        f"Resource did not complete within {timeout_seconds}s: {status_path}. "
        f"Last payload: {last_payload}. Last error: {last_error}"
    )


def assert_pdf_contains_findings(
    pdf_bytes: bytes,
    expected_terms: Iterable[str],
    minimum_size_bytes: int = 800,
) -> None:
    """Assert that a PDF is non-empty and contains expected finding text."""
    assert len(pdf_bytes) >= minimum_size_bytes, (
        f"PDF too small. Got {len(pdf_bytes)} bytes."
    )
    assert pdf_bytes.startswith(b"%PDF-"), "Report body does not start with %PDF-."

    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
    except Exception as error:
        raise AssertionError("Report response could not be parsed as a PDF.") from error

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


def scrape_items_to_jobs(
    scrape_payload: dict[str, Any],
    fallback_url: str,
) -> list[dict[str, str]]:
    """Convert live scrape items into persisted scraped-job payloads."""
    assert scrape_payload.get("success") is True, (
        f"Scrape did not succeed: {scrape_payload}"
    )
    items = scrape_payload.get("items")
    assert isinstance(items, list) and items, (
        f"Scrape completed but returned no items: {scrape_payload}"
    )

    jobs: list[dict[str, str]] = []
    seen_titles: set[str] = set()

    for item in items:
        if not isinstance(item, dict):
            continue

        raw_title = item.get("title")
        title = str(raw_title).strip() if raw_title is not None else ""

        if not title or title in seen_titles:
            continue

        jobs.append(
            {
                "source_url": str(item.get("url") or fallback_url),
                "title": title,
                "company": "Integration Target",
                "location": "Docker Compose",
            }
        )
        seen_titles.add(title)

    assert jobs, f"Scrape items could not be converted into jobs: {items}"
    return jobs


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
        email = f"atta.day21.{unique_suffix}@example.com"
        password = "StrongPassword123!"

        register_response = await client.post(
            endpoints.register,
            json={
                "email": email,
                "password": password,
                "full_name": "Atta Day 21",
            },
        )
        assert_status(
            register_response,
            {200, 201},
            "Register user",
        )

        login_response = await client.post(
            endpoints.login,
            json={
                "email": email,
                "password": password,
            },
        )
        assert_status(login_response, {200}, "Login user")

        login_payload = assert_json_object(login_response, "Login user")
        access_token = assert_bearer_access_token(login_payload)

        malformed_token_response = await client.get(
            endpoints.me,
            headers={"Authorization": "Bearer not-a-jwt"},
        )
        assert_status(
            malformed_token_response,
            {401},
            "Reject malformed bearer token",
        )

        auth_headers = {"Authorization": f"Bearer {access_token}"}

        create_scan_response = await client.post(
            endpoints.create_scan,
            headers=auth_headers,
            json={
                "target_url": target_scan_url,
            },
        )
        assert_status(
            create_scan_response,
            {200, 201, 202},
            "Create scan",
        )

        scan_payload = assert_json_object(create_scan_response, "Create scan")
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
        assert_status(report_response, {200}, "Download scan PDF report")

        content_type = report_response.headers.get("content-type", "")
        assert "application/pdf" in content_type.lower(), (
            "PDF route returned a non-PDF response. "
            f"{response_preview(report_response)}"
        )

        assert_pdf_contains_findings(
            pdf_bytes=report_response.content,
            expected_terms=[
                "severity",
                "finding",
            ],
        )

        scrape_response = await client.post(
            endpoints.scrape_url,
            json={
                "url": target_scan_url,
                "css_selector": "a, h1, tr",
                "use_javascript": False,
            },
        )
        assert_status(
            scrape_response,
            {200},
            "Live scrape target",
        )

        scrape_payload = assert_json_object(scrape_response, "Live scrape target")
        scraped_jobs = scrape_items_to_jobs(scrape_payload, target_scan_url)

        save_scrape_response = await client.post(
            endpoints.save_scrape_results,
            headers=auth_headers,
            json=scraped_jobs,
        )
        assert_status(
            save_scrape_response,
            {201},
            "Save scraped results",
        )

        saved_scrape_payload = assert_json_array(
            save_scrape_response,
            "Save scraped results",
        )
        assert saved_scrape_payload, (
            f"Scrape completed but no rows were saved: {saved_scrape_payload}"
        )

        csv_response = await client.get(
            endpoints.scrape_results_csv_export,
            headers=auth_headers,
        )
        assert_status(csv_response, {200}, "Export scraped results CSV")

        csv_content_type = csv_response.headers.get("content-type", "")
        assert (
            "text/csv" in csv_content_type.lower()
            or "application/octet-stream" in csv_content_type.lower()
        ), f"Unexpected CSV content type: {csv_content_type}"

        assert_csv_has_rows(csv_response.text)
