"""Health endpoint contract tests."""

from fastapi.testclient import TestClient

from restling_server.main import app


def test_health_returns_service_status() -> None:
    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "restling-server",
    }
