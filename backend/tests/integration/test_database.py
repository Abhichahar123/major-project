"""Integration tests against a real PostgreSQL server.

Skipped unless ``TEST_DATABASE_URL`` is set, for example::

    TEST_DATABASE_URL=postgresql+psycopg://cti:password@localhost:5432/cti \
        pytest -m integration
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.db.session import create_db_engine, ping_database
from app.main import create_app
from tests.conftest import make_settings

TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not TEST_DATABASE_URL, reason="TEST_DATABASE_URL is not set"),
]


def test_ping_database_against_real_server() -> None:
    engine = create_db_engine(make_settings(database_url=TEST_DATABASE_URL))
    try:
        assert ping_database(engine) >= 0
    finally:
        engine.dispose()


def test_db_health_endpoint_against_real_server() -> None:
    settings = make_settings(database_url=TEST_DATABASE_URL)
    with TestClient(create_app(settings)) as client:
        response = client.get("/api/v1/health/db")

    assert response.status_code == 200
    assert response.json()["database"] == "ok"


def test_statement_timeout_is_applied() -> None:
    settings = make_settings(database_url=TEST_DATABASE_URL, db_statement_timeout_ms=1234)
    engine = create_db_engine(settings)
    try:
        with engine.connect() as connection:
            assert connection.execute(text("SHOW statement_timeout")).scalar_one() == "1234ms"
    finally:
        engine.dispose()


def test_pgvector_extension_is_available() -> None:
    """Checks the server *can* load pgvector; it is enabled by a migration in Phase 3."""
    if os.environ.get("EXPECT_PGVECTOR", "1") == "0":
        pytest.skip("EXPECT_PGVECTOR=0: server without pgvector")
    engine = create_db_engine(make_settings(database_url=TEST_DATABASE_URL))
    try:
        with engine.connect() as connection:
            available = connection.execute(
                text("SELECT count(*) FROM pg_available_extensions WHERE name = 'vector'")
            ).scalar_one()
    finally:
        engine.dispose()
    assert available == 1, "pgvector is not installed on this PostgreSQL server"
