"""Factories shared by the CLI and the admin API."""

from __future__ import annotations

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from app import __version__
from app.core.config import Settings
from app.ingestion.http import SourceHttpClient


def make_http_client(settings: Settings) -> SourceHttpClient:
    return SourceHttpClient(
        allowed_hosts=settings.ingestion_allowed_hosts,
        timeout_seconds=settings.ingestion_http_timeout_seconds,
        max_retries=settings.ingestion_max_retries,
        backoff_base_seconds=settings.ingestion_backoff_base_seconds,
        max_response_bytes=settings.ingestion_max_response_mb * 1024 * 1024,
        user_agent=f"cti-platform-ingestion/{__version__} (academic project)",
    )


def make_ingestion_engine(settings: Settings) -> Engine:
    """Engine for batch work: same database, longer statement timeout, small pool."""
    url = settings.database_url.get_secret_value()
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url.removeprefix("postgresql://")
    return create_engine(
        url,
        pool_size=2,
        max_overflow=2,
        pool_pre_ping=True,
        hide_parameters=True,
        connect_args={
            "connect_timeout": settings.db_connect_timeout_seconds,
            "options": f"-c statement_timeout={settings.ingestion_statement_timeout_ms}",
            "application_name": "cti-ingestion",
        },
    )


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)
