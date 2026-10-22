"""Liveness and dependency health checks."""

from __future__ import annotations

import logging
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Request, Response, status
from pydantic import BaseModel
from sqlalchemy import Engine

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
