"""Liveness and dependency health checks."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Request, Response, status
from pydantic import BaseModel
from sqlalchemy import Engine, text

from app import __version__
from app.db.session import get_engine, ping_database

logger = logging.getLogger(__name__)

# Mounted under the versioned API prefix.
router = APIRouter(tags=["health"])
# Mounted at the application root, so probes can use a stable unversioned path.
root_router = APIRouter()


class HealthResponse(BaseModel):
    status: Literal["ok"]
    service: str
    version: str


class DatabaseHealthResponse(BaseModel):
    status: Literal["ok", "unavailable"]
    database: Literal["ok", "unreachable"]
    latency_ms: float | None = None


@root_router.get("/health", response_model=HealthResponse, include_in_schema=False)
@router.get("/health", response_model=HealthResponse, summary="Application liveness")
def liveness(request: Request) -> HealthResponse:
    """Report that the process is up. Does not touch the database."""
    return HealthResponse(status="ok", service=request.app.title, version=__version__)


@router.get(
    "/health/db",
    response_model=DatabaseHealthResponse,
    summary="Database connectivity",
    responses={
        status.HTTP_503_SERVICE_UNAVAILABLE: {
            "model": DatabaseHealthResponse,
            "description": "PostgreSQL is unreachable",
        }
    },
)
def database_health(
    response: Response, engine: Annotated[Engine, Depends(get_engine)]
) -> DatabaseHealthResponse:
    """Run a lightweight ``SELECT 1`` against PostgreSQL."""
    try:
        latency_ms = ping_database(engine)
    except Exception as exc:  # any driver or pool error means "unreachable"
        # Log only the exception type: driver messages can include hostnames and usernames.
        logger.warning("Database health check failed", extra={"error_type": type(exc).__name__})
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return DatabaseHealthResponse(status="unavailable", database="unreachable")
    return DatabaseHealthResponse(status="ok", database="ok", latency_ms=latency_ms)


class ReadinessCheck(BaseModel):
    status: Literal["ok", "degraded", "unavailable"]
    detail: str | None = None


class ReadinessResponse(BaseModel):
    status: Literal["ok", "degraded", "unavailable"]
    checks: dict[str, ReadinessCheck]


def _migration_head() -> str | None:
    """Head revision from the Alembic scripts shipped with the application, if present."""
    config_path = Path(__file__).resolve().parents[3] / "alembic.ini"
    if not config_path.exists():
        return None
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    config = Config(str(config_path))
    return ScriptDirectory.from_config(config).get_current_head()


@root_router.get("/health/ready", response_model=ReadinessResponse, include_in_schema=False)
@router.get(
    "/health/ready",
    response_model=ReadinessResponse,
    summary="Readiness: database, schema version and optional components",
    responses={status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ReadinessResponse}},
)
def readiness(
    request: Request, response: Response, engine: Annotated[Engine, Depends(get_engine)]
) -> ReadinessResponse:
    """``unavailable`` (503) only when the API cannot serve data; optional components
    (embeddings, LLM) report ``degraded`` without failing readiness."""
    checks: dict[str, ReadinessCheck] = {}
    try:
        with engine.connect() as connection:
            checks["database"] = ReadinessCheck(status="ok")
            current = connection.execute(text("SELECT version_num FROM alembic_version")).scalar()
            head = getattr(request.app.state, "migration_head", None)
            if head is None:
                head = request.app.state.migration_head = _migration_head()
            if head is None or current == head:
                checks["migrations"] = ReadinessCheck(status="ok", detail=current)
            else:
                checks["migrations"] = ReadinessCheck(
                    status="unavailable", detail=f"database at {current}, code expects {head}"
                )
            vector = connection.execute(
                text("SELECT extversion FROM pg_extension WHERE extname = 'vector'")
            ).scalar()
            checks["pgvector"] = ReadinessCheck(
                status="ok" if vector else "unavailable", detail=vector
            )
    except Exception as exc:
        logger.warning("Readiness check failed", extra={"error_type": type(exc).__name__})
        checks.setdefault("database", ReadinessCheck(status="unavailable"))
        checks.setdefault(
            "migrations", ReadinessCheck(status="unavailable", detail="schema not initialised")
        )
    for name, probe in getattr(request.app.state, "readiness_probes", {}).items():
        checks[name] = probe()
    if any(c.status == "unavailable" for c in checks.values()):
        overall: Literal["ok", "degraded", "unavailable"] = "unavailable"
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    elif any(c.status == "degraded" for c in checks.values()):
        overall = "degraded"
    else:
        overall = "ok"
    return ReadinessResponse(status=overall, checks=checks)
