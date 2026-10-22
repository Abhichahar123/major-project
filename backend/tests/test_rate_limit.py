"""Unit tests for the sliding-window rate limiter and database-outage responses."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.rate_limit import RateLimiter


def test_limiter_allows_up_to_limit_then_blocks() -> None:
    now = [0.0]
    limiter = RateLimiter(clock=lambda: now[0])

    assert [limiter.check("chat", "1.2.3.4", 2) for _ in range(3)][:2] == [0.0, 0.0]
    assert limiter.check("chat", "1.2.3.4", 2) > 0
    assert limiter.check("chat", "5.6.7.8", 2) == 0.0  # other clients are independent
    assert limiter.check("search", "1.2.3.4", 2) == 0.0  # and so are other buckets

    now[0] = 61.0  # the window slides
    assert limiter.check("chat", "1.2.3.4", 2) == 0.0


def test_zero_limit_disables_limiting() -> None:
    limiter = RateLimiter()
    assert all(limiter.check("x", "c", 0) == 0.0 for _ in range(100))


def test_data_endpoint_returns_503_when_database_is_down(client: TestClient) -> None:
    # The default test settings point at 127.0.0.1:1, where nothing listens.
    response = client.get("/api/v1/kev")

    assert response.status_code == 503
    body = response.json()
    assert body["code"] == "database_unavailable"
    assert "127.0.0.1" not in response.text and "test-password" not in response.text


def test_readiness_is_unavailable_without_database(client: TestClient) -> None:
    response = client.get("/health/ready")
    assert response.status_code == 503
    assert response.json()["checks"]["database"]["status"] == "unavailable"
