"""Unit tests for centralized error handling."""

from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.exceptions import PROBLEM_JSON, AppError
from app.main import create_app

SECRET_IN_EXCEPTION = "postgresql://admin:super-secret-pw@db/prod"


@pytest.fixture
def failing_client(settings: Settings) -> TestClient:
    app = create_app(settings)

    @app.get("/boom")
    def boom() -> None:
        raise RuntimeError(f"could not connect to {SECRET_IN_EXCEPTION}")

    @app.get("/teapot")
    def teapot() -> None:
        raise AppError("Short and stout.", status_code=418, code="teapot")

    @app.get("/items/{item_id}")
    def item(item_id: int) -> dict[str, int]:
        return {"item_id": item_id}

    # Starlette re-raises unhandled errors after responding; disable that so we can
    # inspect the response the client actually receives.
    return TestClient(app, raise_server_exceptions=False)


def test_unhandled_exception_returns_generic_500(failing_client: TestClient) -> None:
    response = failing_client.get("/boom")

    assert response.status_code == 500
    assert response.headers["content-type"] == PROBLEM_JSON
    body = response.json()
    assert body["code"] == "internal_error"
    assert body["status"] == 500
    assert body["request_id"] == response.headers["X-Request-ID"]


def test_unhandled_exception_does_not_leak_details(failing_client: TestClient) -> None:
    response = failing_client.get("/boom")

    assert "super-secret-pw" not in response.text
    assert "RuntimeError" not in response.text
    assert "Traceback" not in response.text


def test_unhandled_exception_is_logged_with_secret_redacted(
    failing_client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    # caplog's handler sits on the root logger, so attach the same filter our handler uses.
    from app.core.logging import JsonFormatter, RedactionFilter

    caplog.handler.addFilter(RedactionFilter())
    with caplog.at_level(logging.ERROR):
        failing_client.get("/boom")

    records = [r for r in caplog.records if r.getMessage() == "Unhandled exception"]
    assert records, "the server should log unexpected errors"
    rendered = JsonFormatter().format(records[0])
    assert "RuntimeError" in rendered  # traceback is kept server-side...
    assert "super-secret-pw" not in rendered  # ...with credentials masked


def test_app_error_uses_problem_details(failing_client: TestClient) -> None:
    response = failing_client.get("/teapot")

    assert response.status_code == 418
    assert response.json()["detail"] == "Short and stout."
    assert response.json()["code"] == "teapot"


def test_unknown_route_returns_problem_404(failing_client: TestClient) -> None:
    response = failing_client.get("/does-not-exist")

    assert response.status_code == 404
    assert response.headers["content-type"] == PROBLEM_JSON
    assert response.json()["code"] == "not_found"


def test_validation_error_returns_problem_422_without_echoing_input(
    failing_client: TestClient,
) -> None:
    response = failing_client.get("/items/not-a-number")

    assert response.status_code == 422
    body = response.json()
    assert body["code"] == "validation_error"
    assert body["errors"][0]["loc"] == ["path", "item_id"]
    assert "not-a-number" not in response.text


def test_method_not_allowed_returns_problem_405(failing_client: TestClient) -> None:
    response = failing_client.post("/health")
    assert response.status_code == 405
    assert response.json()["code"] == "method_not_allowed"
