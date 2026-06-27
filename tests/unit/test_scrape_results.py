"""Tests for scraped job CRUD operations and scrape result API endpoints."""

import csv
import io

from pydantic import HttpUrl
from sqlalchemy.orm import Session
from starlette.testclient import TestClient

from security_scanner.crud.scraped_job import create_scraped_job, get_scraped_jobs
from security_scanner.models.user import User
from security_scanner.schemas.scraped_job import ScrapedJobCreate

# ── Base URL ──────────────────────────────────────────────────────────────────

BASE = "/api/v1/scrape"  # change once here if prefix ever changes


# ── Helper ────────────────────────────────────────────────────────────────────


def make_job(url: str, title: str = "Engineer", **kwargs: str) -> ScrapedJobCreate:
    """Build a ScrapedJobCreate without repeating HttpUrl() in every test."""
    return ScrapedJobCreate(
        source_url=HttpUrl(url),
        title=title,
        **kwargs,
    )


# ── CRUD: insert ──────────────────────────────────────────────────────────────


def test_create_scraped_job_inserts_new_row(
    db_session: Session,
    test_user: User,
) -> None:
    """A fresh source_url + title combination is inserted successfully."""
    job = make_job(
        "https://example.com/jobs/1",
        title="Backend Engineer",
        company="Acme Corp",
        location="Remote",
    )

    result = create_scraped_job(db_session, user_id=test_user.id, job_data=job)

    assert result is not None
    assert result.source_url == "https://example.com/jobs/1"
    assert result.title == "Backend Engineer"
    assert result.company == "Acme Corp"
    assert result.location == "Remote"
    assert result.user_id == test_user.id


# ── CRUD: duplicate skipping ──────────────────────────────────────────────────


def test_create_scraped_job_skips_duplicate(
    db_session: Session,
    test_user: User,
) -> None:
    """Inserting the same source_url + title twice returns None on second call."""
    job = make_job("https://example.com/jobs/2", title="Frontend Engineer")

    first = create_scraped_job(db_session, user_id=test_user.id, job_data=job)
    second = create_scraped_job(db_session, user_id=test_user.id, job_data=job)

    assert first is not None
    assert second is None  # duplicate — silently skipped


# ── CRUD: user isolation ──────────────────────────────────────────────────────


def test_different_users_can_scrape_same_url(
    db_session: Session,
    test_user: User,
    other_test_user: User,
) -> None:
    """Two different users can save the same URL — uniqueness is per user."""
    job = make_job("https://example.com/jobs/3", title="DevOps Engineer")

    result_user_one = create_scraped_job(db_session, user_id=test_user.id, job_data=job)
    result_user_two = create_scraped_job(
        db_session,
        user_id=other_test_user.id,
        job_data=job,
    )

    assert result_user_one is not None
    assert result_user_two is not None


def test_get_scraped_jobs_returns_only_user_jobs(
    db_session: Session,
    test_user: User,
    other_test_user: User,
) -> None:
    """get_scraped_jobs never leaks another user's jobs."""
    create_scraped_job(
        db_session,
        user_id=test_user.id,
        job_data=make_job("https://example.com/jobs/4", title="Data Engineer"),
    )
    create_scraped_job(
        db_session,
        user_id=other_test_user.id,
        job_data=make_job("https://example.com/jobs/5", title="ML Engineer"),
    )

    results = get_scraped_jobs(db_session, user_id=test_user.id)

    # test_user should only see their own jobs
    assert all(job.user_id == test_user.id for job in results)


# ── CRUD: filters ─────────────────────────────────────────────────────────────


def test_get_scraped_jobs_filters_by_company(
    db_session: Session,
    test_user: User,
) -> None:
    """get_scraped_jobs returns only jobs matching the given company."""
    create_scraped_job(
        db_session,
        user_id=test_user.id,
        job_data=make_job("https://example.com/jobs/6", title="SRE", company="Google"),
    )
    create_scraped_job(
        db_session,
        user_id=test_user.id,
        job_data=make_job("https://example.com/jobs/7", title="SRE", company="Meta"),
    )

    results = get_scraped_jobs(db_session, user_id=test_user.id, company="Google")

    assert len(results) == 1
    assert results[0].company == "Google"


def test_get_scraped_jobs_filters_by_location(
    db_session: Session,
    test_user: User,
) -> None:
    """get_scraped_jobs returns only jobs matching the given location."""
    create_scraped_job(
        db_session,
        user_id=test_user.id,
        job_data=make_job("https://example.com/jobs/8", title="PM", location="Lahore"),
    )
    create_scraped_job(
        db_session,
        user_id=test_user.id,
        job_data=make_job("https://example.com/jobs/9", title="PM", location="Karachi"),
    )

    results = get_scraped_jobs(db_session, user_id=test_user.id, location="Lahore")

    assert len(results) == 1
    assert results[0].location == "Lahore"


def test_get_scraped_jobs_filters_by_title(
    db_session: Session,
    test_user: User,
) -> None:
    """get_scraped_jobs returns only jobs matching the given title."""
    create_scraped_job(
        db_session,
        user_id=test_user.id,
        job_data=make_job("https://example.com/jobs/10", title="Security Engineer"),
    )
    create_scraped_job(
        db_session,
        user_id=test_user.id,
        job_data=make_job("https://example.com/jobs/11", title="Cloud Engineer"),
    )

    results = get_scraped_jobs(db_session, user_id=test_user.id, title="Security")

    assert len(results) == 1
    assert "Security" in results[0].title


# ── API: save ─────────────────────────────────────────────────────────────────


def test_save_scraped_jobs_returns_201(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    """POST /api/v1/scrape/results returns 201 and the list of saved jobs."""
    payload = [
        {
            "source_url": "https://jobs.example.com/1",
            "title": "Python Developer",
            "company": "Acme",
            "location": "Remote",
        }
    ]

    response = client.post(f"{BASE}/results", json=payload, headers=auth_headers)

    assert response.status_code == 201
    data = response.json()
    assert len(data) == 1
    assert data[0]["title"] == "Python Developer"
    assert data[0]["source_url"] == "https://jobs.example.com/1"


def test_save_scraped_jobs_skips_duplicates(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    """POST /api/v1/scrape/results silently skips jobs that already exist."""
    payload = [{"source_url": "https://jobs.example.com/2", "title": "QA Engineer"}]

    # first request — inserts successfully
    first = client.post(f"{BASE}/results", json=payload, headers=auth_headers)
    assert first.status_code == 201
    assert len(first.json()) == 1

    # second request — duplicate silently skipped
    second = client.post(f"{BASE}/results", json=payload, headers=auth_headers)
    assert second.status_code == 201
    assert len(second.json()) == 0  # nothing new inserted


# ── API: list ─────────────────────────────────────────────────────────────────


def test_list_scraped_jobs_returns_only_own(
    client: TestClient,
    auth_headers: dict[str, str],
    db_session: Session,
    test_user: User,
) -> None:
    """GET /api/v1/scrape/results returns only the authenticated user's jobs."""
    create_scraped_job(
        db_session,
        user_id=test_user.id,
        job_data=make_job("https://jobs.example.com/3", title="Cloud Architect"),
    )

    response = client.get(f"{BASE}/results", headers=auth_headers)

    assert response.status_code == 200
    data = response.json()
    assert all("source_url" in item for item in data)
    assert all("title" in item for item in data)


def test_list_scraped_jobs_filters_by_company(
    client: TestClient,
    auth_headers: dict[str, str],
    db_session: Session,
    test_user: User,
) -> None:
    """GET /api/v1/scrape/results?company=X returns only matching jobs."""
    create_scraped_job(
        db_session,
        user_id=test_user.id,
        job_data=make_job(
            "https://jobs.example.com/4",
            title="Engineer",
            company="Apple",
        ),
    )
    create_scraped_job(
        db_session,
        user_id=test_user.id,
        job_data=make_job(
            "https://jobs.example.com/5",
            title="Engineer",
            company="Microsoft",
        ),
    )

    response = client.get(f"{BASE}/results?company=Apple", headers=auth_headers)

    assert response.status_code == 200
    assert all(item["company"] == "Apple" for item in response.json())


def test_list_scraped_jobs_filters_by_location(
    client: TestClient,
    auth_headers: dict[str, str],
    db_session: Session,
    test_user: User,
) -> None:
    """GET /api/v1/scrape/results?location=X returns only matching jobs."""
    create_scraped_job(
        db_session,
        user_id=test_user.id,
        job_data=make_job("https://jobs.example.com/6", title="PM", location="Lahore"),
    )
    create_scraped_job(
        db_session,
        user_id=test_user.id,
        job_data=make_job("https://jobs.example.com/7", title="PM", location="Karachi"),
    )

    response = client.get(f"{BASE}/results?location=Lahore", headers=auth_headers)

    assert response.status_code == 200
    assert all(item["location"] == "Lahore" for item in response.json())


# ── API: pagination ───────────────────────────────────────────────────────────


def test_list_scraped_jobs_pagination(
    client: TestClient,
    auth_headers: dict[str, str],
    db_session: Session,
    test_user: User,
) -> None:
    """GET /api/v1/scrape/results respects skip and limit query parameters."""
    for i in range(5):
        create_scraped_job(
            db_session,
            user_id=test_user.id,
            job_data=make_job(
                f"https://jobs.example.com/page/{i}",
                title=f"Engineer {i}",
            ),
        )

    response = client.get(f"{BASE}/results?skip=0&limit=2", headers=auth_headers)

    assert response.status_code == 200
    assert len(response.json()) == 2


def test_list_scraped_jobs_second_page(
    client: TestClient,
    auth_headers: dict[str, str],
    db_session: Session,
    test_user: User,
) -> None:
    """GET /api/v1/scrape/results?skip=2&limit=2 returns the second page."""
    for i in range(4):
        create_scraped_job(
            db_session,
            user_id=test_user.id,
            job_data=make_job(
                f"https://jobs.example.com/paged/{i}",
                title=f"Role {i}",
            ),
        )

    response = client.get(f"{BASE}/results?skip=2&limit=2", headers=auth_headers)

    assert response.status_code == 200
    assert len(response.json()) == 2


# ── API: export ───────────────────────────────────────────────────────────────


def test_export_returns_valid_csv(
    client: TestClient,
    auth_headers: dict[str, str],
    db_session: Session,
    test_user: User,
) -> None:
    """GET /api/v1/scrape/results/export returns valid CSV with correct headers."""
    create_scraped_job(
        db_session,
        user_id=test_user.id,
        job_data=make_job(
            "https://jobs.example.com/export/1",
            title="Security Engineer",
            company="CyberCorp",
            location="Remote",
        ),
    )

    response = client.get(f"{BASE}/results/export", headers=auth_headers)

    assert response.status_code == 200
    assert "text/csv" in response.headers["content-type"]

    rows = list(csv.reader(io.StringIO(response.text)))

    # verify correct CSV headers matching model fields
    assert rows[0] == [
        "id",
        "source_url",
        "title",
        "company",
        "location",
        "date_posted",
        "scraped_at",
    ]
    assert len(rows) == 2  # header + 1 data row


def test_export_empty_when_no_jobs(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    """GET /api/v1/scrape/results/export returns only header when no jobs exist."""
    response = client.get(f"{BASE}/results/export", headers=auth_headers)

    assert response.status_code == 200

    rows = list(csv.reader(io.StringIO(response.text)))

    # only header row, no data
    assert len(rows) == 1
    assert rows[0][0] == "id"


# ── API: auth guards ──────────────────────────────────────────────────────────


def test_list_scraped_jobs_requires_authentication(client: TestClient) -> None:
    """GET /api/v1/scrape/results returns 401 without authentication."""
    response = client.get(f"{BASE}/results")
    assert response.status_code == 401


def test_save_scraped_jobs_requires_authentication(client: TestClient) -> None:
    """POST /api/v1/scrape/results returns 401 without authentication."""
    payload = [{"source_url": "https://jobs.example.com/x", "title": "Dev"}]
    response = client.post(f"{BASE}/results", json=payload)
    assert response.status_code == 401


def test_export_requires_authentication(client: TestClient) -> None:
    """GET /api/v1/scrape/results/export returns 401 without authentication."""
    response = client.get(f"{BASE}/results/export")
    assert response.status_code == 401
