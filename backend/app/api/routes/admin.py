"""Administrative operations, protected by ``X-Admin-Key``."""

from __future__ import annotations

import logging

from fastapi import APIRouter, BackgroundTasks, Depends, Request, status

from app.api.deps import DbSession
from app.api.routes.catalog import job_detail
from app.core.exceptions import AppError
from app.core.rate_limit import rate_limit
from app.core.security import require_admin
from app.ingestion.jobs import JobConflictError, create_job, execute_job
from app.ingestion.sources import ParamError, get_adapter
from app.schemas.vulnerabilities import JobAccepted, JobCreate, JobDetail

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(rate_limit("admin")), Depends(require_admin)],
)


def _run_in_background(request: Request, job_id: int, source: str) -> None:
    state = request.app.state
    try:
        execute_job(
            job_id,
            get_adapter(source),
            state.settings,
            state.ingestion_session_factory,
            state.http_factory,
        )
    except Exception:  # execute_job records failures itself; this guards setup errors
        logger.exception("Background ingestion job crashed", extra={"job_id": job_id})


@router.post("/ingestion/jobs", status_code=status.HTTP_202_ACCEPTED, response_model=JobAccepted)
def start_job(body: JobCreate, request: Request, background: BackgroundTasks) -> JobAccepted:
    """Queue an ingestion job and run it in the background.

    ``params`` are validated by the source adapter (e.g. ``{"mode": "ids", "ids":
    ["CVE-2021-44228"]}`` for ``cve5``). Only one job per source may be active.
    """
    state = request.app.state
    try:
        adapter = get_adapter(body.source)
        job_id = create_job(
            state.ingestion_session_factory, state.settings, adapter, body.params, trigger="api"
        )
    except ParamError as exc:
        raise AppError(str(exc), status_code=422, code="invalid_job_params") from None
    except JobConflictError as exc:
        raise AppError(str(exc), status_code=409, code="job_conflict") from None
    background.add_task(_run_in_background, request, job_id, body.source)
    prefix = state.settings.api_v1_prefix
    return JobAccepted(
        job_id=job_id,
        source=body.source,
        status="queued",
        status_url=f"{prefix}/ingestion/jobs/{job_id}",
    )


@router.get("/ingestion/jobs/{job_id}", response_model=JobDetail)
def get_job_with_errors(job_id: int, db: DbSession) -> JobDetail:
    """Job status including the first 100 per-record errors."""
    return job_detail(db, job_id)
