"""Unit tests for the CORS allowlist."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app
from tests.conftest import make_settings

ALLOWED = "http://localhost:3000"


def _client(**overrides: object) -> TestClient:
    return TestClient(create_app(make_settings(**overrides)))


def test_allowed_origin_receives_cors_header() -> None:
    response = _client(cors_origins=[ALLOWED]).get("/health", headers={"Origin": ALLOWED})

    assert response.headers["access-control-allow-origin"] == ALLOWED


def test_disallowed_origin_receives_no_cors_header() -> None:
    response = _client(cors_origins=[ALLOWED]).get(
        "/health", headers={"Origin": "https://evil.example"}
    )

    assert "access-control-allow-origin" not in response.headers


def test_preflight_for_disallowed_origin_is_rejected() -> None:
    response = _client(cors_origins=[ALLOWED]).options(
        "/api/v1/health",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
    )

    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers


def test_preflight_for_allowed_origin_succeeds() -> None:
    response = _client(cors_origins=[ALLOWED]).options(
        "/api/v1/health",
        headers={"Origin": ALLOWED, "Access-Control-Request-Method": "GET"},
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == ALLOWED


def test_no_origins_configured_means_no_cross_origin_access() -> None:
    response = _client().get("/health", headers={"Origin": ALLOWED})

    assert "access-control-allow-origin" not in response.headers
