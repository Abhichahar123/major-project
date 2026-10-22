"""Application entry point.

Run with ``uvicorn app.main:app`` from the ``backend`` directory.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.routes import health
from app.core.config import Settings, get_settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import RequestContextMiddleware, configure_logging
from app.db.session import create_db_engine, create_session_factory

logger = logging.getLogger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the FastAPI application. Configuration is validated here, at startup."""
    settings = settings or get_settings()
    configure_logging(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = create_db_engine(settings)
        app.state.db_engine = engine
        app.state.db_session_factory = create_session_factory(engine)
        logger.info(
            "Application started",
            extra={
                "environment": settings.environment.value,
                "admin_operations_enabled": settings.admin_operations_enabled,
            },
        )
        try:
            yield
        finally:
            engine.dispose()
            logger.info("Application stopped")

    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        lifespan=lifespan,
        # Interactive docs are useful locally but not exposed in production.
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None,
        openapi_url=None if settings.is_production else f"{settings.api_v1_prefix}/openapi.json",
    )
    app.state.settings = settings

    register_exception_handlers(app)

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=False,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Content-Type", "X-Request-ID", "X-Admin-Key"],
            expose_headers=["X-Request-ID"],
        )
    # Added last so it wraps everything else, including CORS.
    app.add_middleware(RequestContextMiddleware)

    # Unversioned liveness probe for load balancers and container health checks.
    app.include_router(health.root_router)

    api_v1 = APIRouter(prefix=settings.api_v1_prefix)
    api_v1.include_router(health.router)
    app.include_router(api_v1)

    return app


app = create_app()
