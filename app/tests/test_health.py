from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_returns_ok_and_timestamp() -> None:
    """Verify the health endpoint returns API status and timestamp."""
    response = client.get("/health")

    assert response.status_code == 200

    response_body = response.json()

    assert response_body["status"] == "ok"
    assert "timestamp" in response_body