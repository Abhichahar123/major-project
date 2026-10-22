"""Security headers and request-size limits."""

from __future__ import annotations

from fastapi import Request
from fastapi.testclient import TestClient

from app.main import create_app
from tests.conftest import make_settings


def test_security_headers_on_api_responses(client: TestClient) -> None:
    response = client.get("/health")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "default-src 'none'" in response.headers["content-security-policy"]


def test_docs_page_keeps_working_without_strict_csp(client: TestClient) -> None:
    response = client.get("/docs")
    assert response.status_code == 200
    assert "content-security-policy" not in response.headers


def test_docs_disabled_in_production() -> None:
    settings = make_settings(
        environment="production",
        admin_api_key="k" * 40,
        cors_origins=["https://app.example.org"],
        llm_provider="none",
    )
    with TestClient(create_app(settings)) as client:
        assert client.get("/docs").status_code == 404
        assert client.get("/api/v1/openapi.json").status_code == 404


def _echo_app(limit: int) -> TestClient:
    app = create_app(make_settings(max_request_body_bytes=limit))

    @app.post("/echo")
    async def echo(request: Request) -> dict[str, int]:
        return {"size": len(await request.body())}

    return TestClient(app)


def test_body_limit_by_content_length() -> None:
    client = _echo_app(64 * 1024)
    assert client.post("/echo", content=b"x" * 1000).json() == {"size": 1000}
    response = client.post("/echo", content=b"x" * (64 * 1024 + 1))
    assert response.status_code == 413
    assert response.json()["code"] == "body_too_large"


def test_body_limit_for_streamed_body_without_length() -> None:
    client = _echo_app(64 * 1024)

    def chunks():  # type: ignore[no-untyped-def]
        for _ in range(100):
            yield b"x" * 1024

    response = client.post("/echo", content=chunks())
    assert response.status_code == 413
