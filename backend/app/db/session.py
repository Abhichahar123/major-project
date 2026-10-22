"""SQLAlchemy engine and session management.

The engine is created in the application lifespan (not at import time) and is
stored on ``app.state``. SQLAlchemy connects lazily, so creating the engine does
not open a connection; the first query does.
"""

from __future__ import annotations

import time
from collections.abc import Iterator

from fastapi import Request
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings


def create_db_engine(settings: Settings) -> Engine:
    url = settings.database_url.get_secret_value()
    if url.startswith("postgresql://"):
        # Use psycopg 3 rather than SQLAlchemy's default psycopg2 driver.
        url = "postgresql+psycopg://" + url.removeprefix("postgresql://")
    return create_engine(
        url,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_pre_ping=True,
        hide_parameters=True,  # keep bound parameter values out of error messages and logs
        connect_args={
            "connect_timeout": settings.db_connect_timeout_seconds,
            "options": f"-c statement_timeout={settings.db_statement_timeout_ms}",
            "application_name": "cti-backend",
        },
    )


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def ping_database(engine: Engine) -> float:
    """Run ``SELECT 1`` and return the round-trip time in milliseconds.

    Raises ``sqlalchemy.exc.SQLAlchemyError`` (or a driver error) on failure.
    """
    start = time.perf_counter()
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    return round((time.perf_counter() - start) * 1000, 2)


def get_engine(request: Request) -> Engine:
    """FastAPI dependency returning the application's engine."""
    engine: Engine = request.app.state.db_engine
    return engine


def get_db_session(request: Request) -> Iterator[Session]:
    """FastAPI dependency yielding a session that is always closed afterwards."""
    session_factory: sessionmaker[Session] = request.app.state.db_session_factory
    with session_factory() as session:
        yield session
