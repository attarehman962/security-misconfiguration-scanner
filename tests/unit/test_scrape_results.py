"""Tests for scraped job CRUD operations and scrape result API endpoints.

Coverage:
- CRUD: insert, duplicate skipping, user isolation, filters
- API:  save, list, filter, paginate, export, auth guards
"""

# ruff: noqa: ANN001, ANN003, ANN201

import csv
import io

from pydantic import HttpUrl

from security_scanner.crud.scraped_job import create_scraped_job, get_scraped_jobs
from security_scanner.schemas.scraped_job import ScrapedJobCreate

SCRAPE_RESULTS_URL = "/api/v1/scrape/results"
SCRAPE_RESULTS_EXPORT_URL = f"{SCRAPE_RESULTS_URL}/export"


# ── Test helper ───────────────────────────────────────────────────────────────

def make_job(url: str, title: str = "Engineer", **kwargs) -> ScrapedJobCreate:
    """Build a ScrapedJobCreate without repeating HttpUrl() in every test."""
    return ScrapedJobCreate(
        source_url=HttpUrl(url),
        title=title,
        **kwargs,
    )


# ── CRUD: insert ──────────────────────────────────────────────────────────────

def test_create_scraped_job_inserts_new_row(db_session, test_user):
    """A fresh source_url + title combination is inserted successfully."""
    job = make_job(
        "https://example.com/jobs/1",
        title="Backend Engineer",
        company="Acme Corp",
        location="Remote",
    )

    result = create_scraped_job(db_session, user_id=test_user.id, job_data=job)

    # job should be created with correct fields
    assert result is not None
    assert result.source_url == "https://example.com/jobs/1"
    assert result.title == "Backend Engineer"
    assert result.company == "Acme Corp"
    assert result.location == "Remote"
    assert result.user_id == test_user.id


# ── CRUD: duplicate skipping ──────────────────────────────────────────────────

def test_create_scraped_job_skips_duplicate(db_session, test_user):
    """Inserting the same source_url + title twice returns None on second call."""
    job = make_job("https://example.com/jobs/2", title="Frontend Engineer")

    first = create_scraped_job(db_session, user_id=test_user.id, job_data=job)
    second = create_scraped_job(db_session, user_id=test_user.id, job_data=job)

    # first insert succeeds
    assert first is not None

    # second insert is silently skipped — idempotent
    assert second is None


# ── CRUD: user isolation ──────────────────────────────────────────────────────

def test_different_users_can_scrape_same_url(db_session, test_user, other_test_user):
    """Two different users can save the same URL — uniqueness is per user."""
    job = make_job("https://example.com/jobs/3", title="DevOps Engineer")

    result_user_one = create_scraped_job(db_session, user_id=test_user.id, job_data=job)
    result_user_two = create_scraped_job(
        db_session,
        user_id=other_test_user.id,
        job_data=job,
    )

    # both should succeed independently
    assert result_user_one is not None
    assert result_user_two is not None


def test_get_scraped_jobs_returns_only_user_jobs(
    db_session,
    test_user,
    other_test_user,
):
    """get_scraped_jobs never leaks another user's jobs."""
    # insert one job for test_user
    create_scraped_job(
        db_session,
        user_id=test_user.id,
        job_data=make_job("https://example.com/jobs/4", title="Data Engineer"),
    )

    # insert one job for other_test_user
    create_scraped_job(
        db_session,
        user_id=other_test_user.id,
        job_data=make_job("https://example.com/jobs/5", title="ML Engineer"),
    )

    results = get_scraped_jobs(db_session, user_id=test_user.id)

    # test_user should only see their own job
    assert all(job.user_id == test_user.id for job in results)


# ── CRUD: filters ─────────────────────────────────────────────────────────────

def test_get_scraped_jobs_filters_by_company(db_session, test_user):
    """get_scraped_jobs returns only jobs matching the given company."""
    # insert two jobs with different companies
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

    # only Google job should be returned
    assert len(results) == 1
    assert results[0].company == "Google"


def test_get_scraped_jobs_filters_by_location(db_session, test_user):
    """get_scraped_jobs returns only jobs matching the given location."""
    # insert two jobs with different locations
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

    # only Lahore job should be returned
    assert len(results) == 1
    assert results[0].location == "Lahore"


def test_get_scraped_jobs_filters_by_title(db_session, test_user):
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

    # only Security Engineer should match
    assert len(results) == 1
    assert "Security" in results[0].title


# ── API: save ─────────────────────────────────────────────────────────────────

def test_save_scraped_jobs_returns_201(client, auth_headers):
    """POST /api/v1/scrape/results returns 201 and the saved jobs."""
    payload = [
        {
            "source_url": "https://jobs.example.com/1",
            "title": "Python Developer",
            "company": "Acme",
            "location": "Remote",
        }
    ]

    response = client.post(
        SCRAPE_RESULTS_URL,
        json=payload,
        headers=auth_headers,
    )

    assert response.status_code == 201

    data = response.json()
    assert len(data) == 1
    assert data[0]["title"] == "Python Developer"
    assert data[0]["source_url"] == "https://jobs.example.com/1"


def test_save_scraped_jobs_skips_duplicates(client, auth_headers):
    """POST /api/v1/scrape/results silently skips existing jobs."""
    payload = [
        {
            "source_url": "https://jobs.example.com/2",
            "title": "QA Engineer",
        }
    ]

    # first request — inserts successfully
    first = client.post(SCRAPE_RESULTS_URL, json=payload, headers=auth_headers)
    assert first.status_code == 201
    assert len(first.json()) == 1

    # second request — duplicate silently skipped
    second = client.post(SCRAPE_RESULTS_URL, json=payload, headers=auth_headers)
    assert second.status_code == 201
    assert len(second.json()) == 0  # nothing new inserted


# ── API: list ─────────────────────────────────────────────────────────────────

def test_list_scraped_jobs_returns_only_own(
    client,
    auth_headers,
    db_session,
    test_user,
):
    """GET /api/v1/scrape/results returns only the authenticated user's jobs."""
    create_scraped_job(
        db_session,
        user_id=test_user.id,
        job_data=make_job("https://jobs.example.com/3", title="Cloud Architect"),
    )

    response = client.get(SCRAPE_RESULTS_URL, headers=auth_headers)

    assert response.status_code == 200

    # every returned job should have expected fields
    data = response.json()
    assert all("source_url" in item for item in data)
    assert all("title" in item for item in data)


def test_list_scraped_jobs_filters_by_company(
    client,
    auth_headers,
    db_session,
    test_user,
):
    """GET /api/v1/scrape/results?company=X filters by company."""
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

    response = client.get(f"{SCRAPE_RESULTS_URL}?company=Apple", headers=auth_headers)

    assert response.status_code == 200
    assert all(item["company"] == "Apple" for item in response.json())


def test_list_scraped_jobs_filters_by_location(
    client,
    auth_headers,
    db_session,
    test_user,
):
    """GET /api/v1/scrape/results?location=X filters by location."""
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

    response = client.get(f"{SCRAPE_RESULTS_URL}?location=Lahore", headers=auth_headers)

    assert response.status_code == 200
    assert all(item["location"] == "Lahore" for item in response.json())


# ── API: pagination ───────────────────────────────────────────────────────────

def test_list_scraped_jobs_pagination(client, auth_headers, db_session, test_user):
    """GET /api/v1/scrape/results respects skip and limit query parameters."""
    # insert 5 jobs
    for i in range(5):
        create_scraped_job(
            db_session,
            user_id=test_user.id,
            job_data=make_job(
                f"https://jobs.example.com/page/{i}",
                title=f"Engineer {i}",
            ),
        )

    # request only 2 at a time
    response = client.get(f"{SCRAPE_RESULTS_URL}?skip=0&limit=2", headers=auth_headers)

    assert response.status_code == 200
    assert len(response.json()) == 2


def test_list_scraped_jobs_second_page(client, auth_headers, db_session, test_user):
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

    response = client.get(f"{SCRAPE_RESULTS_URL}?skip=2&limit=2", headers=auth_headers)

    assert response.status_code == 200
    assert len(response.json()) == 2


# ── API: export ───────────────────────────────────────────────────────────────

def test_export_returns_valid_csv(client, auth_headers, db_session, test_user):
    """GET /api/v1/scrape/results/export returns valid CSV."""
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

    response = client.get(SCRAPE_RESULTS_EXPORT_URL, headers=auth_headers)

    assert response.status_code == 200
    assert "text/csv" in response.headers["content-type"]

    rows = list(csv.reader(io.StringIO(response.text)))

    # verify correct CSV column headers matching our model fields
    assert rows[0] == [
        "id", "source_url", "title",
        "company", "location", "date_posted", "scraped_at",
    ]

    # header + 1 data row
    assert len(rows) == 2


def test_export_empty_when_no_jobs(client, auth_headers):
    """GET /api/v1/scrape/results/export returns only headers when empty."""
    response = client.get(SCRAPE_RESULTS_EXPORT_URL, headers=auth_headers)

    assert response.status_code == 200

    rows = list(csv.reader(io.StringIO(response.text)))

    # only header, no data rows
    assert len(rows) == 1
    assert rows[0][0] == "id"


# ── API: auth guards ──────────────────────────────────────────────────────────

def test_list_scraped_jobs_requires_authentication(client):
    """GET /api/v1/scrape/results returns 401 without authentication."""
    response = client.get(SCRAPE_RESULTS_URL)
    assert response.status_code == 401


def test_save_scraped_jobs_requires_authentication(client):
    """POST /api/v1/scrape/results returns 401 without authentication."""
    payload = [{"source_url": "https://jobs.example.com/x", "title": "Dev"}]
    response = client.post(SCRAPE_RESULTS_URL, json=payload)
    assert response.status_code == 401


def test_export_requires_authentication(client):
    """GET /api/v1/scrape/results/export returns 401 without authentication."""
    response = client.get(SCRAPE_RESULTS_EXPORT_URL)
    assert response.status_code == 401
