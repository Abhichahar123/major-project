"""CISA KEV listing, ATT&CK techniques, data sources, ingestion status and statistics."""

from __future__ import annotations

from datetime import date
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, status

from app.api.deps import DbSession, PageQuery, PageSizeQuery, SearchText, TechniqueIdPath
from app.core.exceptions import AppError
from app.core.rate_limit import rate_limit
from app.schemas.common import Page
from app.schemas.vulnerabilities import (
    JobDetail,
    JobOut,
    KevListItem,
    SourceStatus,
    Stats,
    TechniqueDetail,
    TechniqueSummary,
)
from app.services import catalog

router = APIRouter(dependencies=[Depends(rate_limit("search"))])

JobStatus = Literal["queued", "running", "succeeded", "partial", "failed"]


@router.get("/kev", response_model=Page[KevListItem], tags=["kev"])
def list_kev(
    db: DbSession,
    q: SearchText = None,
    vendor: Annotated[str | None, Query(min_length=1, max_length=100)] = None,
    ransomware: Literal["Known", "Unknown"] | None = None,
    cwe: Annotated[str | None, Query(pattern=r"^CWE-\d{1,5}$")] = None,
    date_added_from: date | None = None,
    date_added_to: date | None = None,
    page: PageQuery = 1,
    page_size: PageSizeQuery = 20,
) -> Page[KevListItem]:
    """CISA Known Exploited Vulnerabilities, newest additions first."""
    filters = catalog.KevFilters(
        q=q,
        vendor=vendor,
        ransomware=ransomware,
        cwe=cwe,
        date_added_from=date_added_from,
        date_added_to=date_added_to,
    )
    items, total = catalog.list_kev(db, filters, page, page_size)
    return Page(
        items=[KevListItem(**i) for i in items], page=page, page_size=page_size, total=total
    )


@router.get("/techniques", response_model=Page[TechniqueSummary], tags=["attack"])
def list_techniques(
    db: DbSession,
    q: SearchText = None,
    tactic: Annotated[str | None, Query(pattern=r"^[a-z][a-z-]{1,40}$")] = None,
    platform: Annotated[str | None, Query(min_length=1, max_length=40)] = None,
    include_deprecated: bool = False,
    page: PageQuery = 1,
    page_size: PageSizeQuery = 20,
) -> Page[TechniqueSummary]:
    """MITRE ATT&CK Enterprise techniques (``tactic`` uses ATT&CK phase names, e.g.
    ``initial-access``)."""
    items, total = catalog.list_techniques(
        db, q, tactic, platform, include_deprecated, page, page_size
    )
    return Page(
        items=[TechniqueSummary.model_validate(i) for i in items],
        page=page,
        page_size=page_size,
        total=total,
    )


@router.get("/techniques/{technique_id}", response_model=TechniqueDetail, tags=["attack"])
def get_technique(technique_id: TechniqueIdPath, db: DbSession) -> TechniqueDetail:
    found = catalog.get_technique(db, technique_id.upper())
    if found is None:
        raise AppError(
            f"Technique {technique_id.upper()} not found.",
            status_code=status.HTTP_404_NOT_FOUND,
            code="technique_not_found",
        )
    return TechniqueDetail.model_validate(found)


@router.get("/sources", response_model=list[SourceStatus], tags=["sources"])
def list_sources(db: DbSession) -> list[SourceStatus]:
    """Registered data sources with last successful sync and latest job."""
    return [SourceStatus(**s) for s in catalog.list_sources(db)]


@router.get("/ingestion/jobs", response_model=Page[JobOut], tags=["sources"])
def list_jobs(
    db: DbSession,
    source: Annotated[str | None, Query(pattern=r"^[a-z0-9]{2,32}$")] = None,
    status_: Annotated[JobStatus | None, Query(alias="status")] = None,
    page: PageQuery = 1,
    page_size: PageSizeQuery = 20,
) -> Page[JobOut]:
    items, total = catalog.list_jobs(db, source, status_, page, page_size)
    return Page(items=[JobOut(**i) for i in items], page=page, page_size=page_size, total=total)


@router.get("/ingestion/jobs/{job_id}", response_model=JobOut, tags=["sources"])
def get_job(job_id: int, db: DbSession) -> JobOut:
    """Job status and counts. Per-record errors are available to admins only."""
    found = catalog.get_job(db, job_id, include_errors=False)
    if found is None:
        raise AppError(f"Job {job_id} not found.", status_code=404, code="job_not_found")
    return JobOut(**{k: v for k, v in found.items() if k != "errors"})


@router.get("/stats", response_model=Stats, tags=["stats"])
def get_stats(db: DbSession) -> Stats:
    """Dashboard counts computed from the local database."""
    return Stats(**catalog.stats(db))


def job_detail(db: DbSession, job_id: int) -> JobDetail:
    found = catalog.get_job(db, job_id, include_errors=True)
    if found is None:
        raise AppError(f"Job {job_id} not found.", status_code=404, code="job_not_found")
    return JobDetail.model_validate(found)
