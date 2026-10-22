"""Unit tests for the health endpoints (no live database required)."""

from __future__ import annotations

from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from app import __version__
from app.db.session import get_engine


def test_root_health_returns_ok(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "Cyber Threat Intelligence API",
        "version": __version__,
    }
    assert response.headers["X-Request-ID"]


def test_versioned_health_returns_ok(client: TestClient) -> None:
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_db_health_is_only_under_versioned_prefix(client: TestClient) -> None:
    assert client.get("/health/db").status_code == 404


def test_db_health_ok_when_database_responds(client: TestClient) -> None:
    fake_engine = MagicMock()  # engine.connect() context manager succeeds
    client.app.dependency_overrides[get_engine] = lambda: fake_engine  # type: ignore[attr-defined]

    response = client.get("/api/v1/health/db")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["database"] == "ok"
    assert isinstance(body["latency_ms"], float)
    fake_engine.connect.return_value.__enter__.return_value.execute.assert_called_once()


def test_db_health_503_when_database_unreachable(client: TestClient) -> None:
    # The default test settings point at 127.0.0.1:1, where nothing listens, so this
    # exercises the real driver failure path rather than a mock.
    response = client.get("/api/v1/health/db")

    assert response.status_code == 503
    assert response.json() == {
        "status": "unavailable",
        "database": "unreachable",
        "latency_ms": None,
    }


def test_db_health_failure_does_not_leak_connection_details(client: TestClient) -> None:
    response = client.get("/api/v1/health/db")

    assert "test-password" not in response.text
    assert "127.0.0.1" not in response.text
    assert "test_user" not in response.text


def test_request_id_is_echoed_when_valid(client: TestClient) -> None:
    response = client.get("/health", headers={"X-Request-ID": "abc-123"})
    assert response.headers["X-Request-ID"] == "abc-123"


def test_invalid_request_id_is_replaced(client: TestClient) -> None:
    response = client.get("/health", headers={"X-Request-ID": "bad id with spaces"})
    assert response.headers["X-Request-ID"] != "bad id with spaces"
