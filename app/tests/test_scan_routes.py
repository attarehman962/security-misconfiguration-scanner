from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_scan_accepts_valid_url_and_returns_mock_result() -> None:
    """Verify POST /scan accepts a valid URL and returns scan response."""
    response = client.post(
        "/scan",
        json={"url": "https://example.com"},
    )

    assert response.status_code == 200

    response_body = response.json()

    assert response_body["url"].startswith("https://example.com")
    assert response_body["total_score"] == 85
    assert isinstance(response_body["findings"], list)
    assert response_body["findings"][0]["check_name"] == "security_headers"
    assert response_body["findings"][0]["status"] == "fail"
    assert response_body["findings"][0]["severity"] == "medium"


def test_scan_rejects_invalid_url_with_custom_422_response() -> None:
    """Verify invalid URLs return the custom validation response."""
    response = client.post(
        "/scan",
        json={"url": "not-a-valid-url"},
    )

    assert response.status_code == 422

    response_body = response.json()

    assert response_body["message"] == (
        "Request validation failed. Check the submitted fields."
    )
    assert isinstance(response_body["errors"], list)
    assert response_body["errors"][0]["field"] == "body.url"
    assert "message" in response_body["errors"][0]
    assert "error_type" in response_body["errors"][0]


def test_scan_rejects_missing_url() -> None:
    """Verify POST /scan rejects requests without the required URL field."""
    response = client.post("/scan", json={})

    assert response.status_code == 422

    response_body = response.json()

    assert response_body["message"] == (
        "Request validation failed. Check the submitted fields."
    )
    assert response_body["errors"][0]["field"] == "body.url"


def test_get_scans_returns_empty_list() -> None:
    """Verify GET /scans returns empty scan history for Day 10."""
    response = client.get("/scans")

    assert response.status_code == 200
    assert response.json() == []