"""Fixtures for tests that need a real PostgreSQL with pgvector.

``TEST_DATABASE_URL`` must point at a dedicated, disposable database: the session fixture
drops and re-creates the schema with Alembic. As a guard, the database name must contain
"test".
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL")
BACKEND_DIR = Path(__file__).resolve().parents[2]

# Reference rows inserted by the initial migration; kept between tests.
_PRESERVED_TABLES = {"sources", "alembic_version"}


def _require_url() -> str:
    if not TEST_DATABASE_URL:
        pytest.skip("TEST_DATABASE_URL is not set")
    database = make_url(TEST_DATABASE_URL).database or ""
    if "test" not in database:
        pytest.fail(
            f"Refusing to run destructive tests against database {database!r}: "
            "its name must contain 'test'."
        )
    return TEST_DATABASE_URL


def alembic_config(url: str) -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    config.cmd_opts = type("Opts", (), {"x": [f"database_url={url}"]})()  # type: ignore[assignment]
    return config


@pytest.fixture(scope="session")
def database_url() -> str:
    return _require_url()


@pytest.fixture(scope="session")
def migrated_engine(database_url: str) -> Iterator[Engine]:
    config = alembic_config(database_url)
    command.downgrade(config, "base")
    command.upgrade(config, "head")
    engine = create_engine(database_url.replace("postgresql://", "postgresql+psycopg://", 1))
    try:
        yield engine
    finally:
        engine.dispose()


def truncate_all(engine: Engine) -> None:
    with engine.begin() as connection:
        tables = connection.execute(
            text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
        ).scalars()
        names = [name for name in tables if name not in _PRESERVED_TABLES]
        if names:
            quoted = ", ".join(f'"{name}"' for name in names)
            connection.execute(text(f"TRUNCATE {quoted} RESTART IDENTITY CASCADE"))
        connection.execute(text("UPDATE sources SET watermark = NULL, last_success_at = NULL"))


@pytest.fixture
def session_factory(migrated_engine: Engine) -> Iterator[sessionmaker[Session]]:
    truncate_all(migrated_engine)
    yield sessionmaker(bind=migrated_engine, expire_on_commit=False)
    truncate_all(migrated_engine)


@pytest.fixture
def db(session_factory: sessionmaker[Session]) -> Iterator[Session]:
    with session_factory() as session:
        yield session
