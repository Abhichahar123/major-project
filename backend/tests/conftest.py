"""Shared fixtures.

Unit tests never need a live database: the engine is created lazily, and the
database health tests either override the engine dependency or point it at a
port where nothing is listening.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import Any

import pytest

# Importing app.main builds the module-level app, so give it a valid environment
# before any test module imports it. These values are not real credentials.
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault(
    "DATABASE_URL", "postgresql+psycopg://test_user:test-password@127.0.0.1:1/test_db"
)

from fastapi.testclient import TestClient

from app.core.config import Settings, get_settings
from app.main import create_app

UNREACHABLE_DB_URL = "postgresql+psycopg://test_user:test-password@127.0.0.1:1/test_db"


@pytest.fixture(autouse=True)
def _isolate_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Keep a developer's .env file and real environment out of unit tests."""
    monkeypatch.chdir(os.path.dirname(__file__))  # no .env in tests/
    for name in (
        "ADMIN_API_KEY",
        "CORS_ORIGINS",
        "LOG_LEVEL",
        "LOG_FORMAT",
        "API_V1_PREFIX",
        # A developer's real Gemini key must never reach a test (or a mocked request).
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "GEMINI_MODEL",
        "GEMINI_EMBEDDING_MODEL",
        "GEMINI_THINKING_BUDGET",
    ):
        monkeypatch.delenv(name, raising=False)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def make_settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "environment": "test",
        "database_url": UNREACHABLE_DB_URL,
        "db_connect_timeout_seconds": 1,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)  # type: ignore[call-arg]


@pytest.fixture
def settings() -> Settings:
    return make_settings()


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(settings)) as test_client:
        yield test_client
