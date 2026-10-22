"""Vulnerability search and CVE detail."""

from __future__ import annotations

from datetime import date
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, status

from app.api.deps import CveIdPath, DbSession, PageQuery, PageSizeQuery, SearchText
from app.core.exceptions import AppError
from app.core.rate_limit import rate_limit
from app.schemas.common import Page, Severity
from app.schemas.vulnerabilities import VulnerabilityDetail, VulnerabilitySummary
from app.services.catalog import (
    VulnerabilityFilters,
    get_vulnerability_detail,
    search_vulnerabilities,
)

router = APIRouter(tags=["vulnerabilities"], dependencies=[Depends(rate_limit("search"))])


@router.get("/vulnerabilities", response_model=Page[VulnerabilitySummary])
def search(
    db: DbSession,
    q: SearchText = None,
    severity: Annotated[list[Severity], Query(description="Repeat to match several")] = [],  # noqa: B006
    min_cvss: Annotated[float | None, Query(ge=0, le=10)] = None,
    max_cvss: Annotated[float | None, Query(ge=0, le=10)] = None,
    cwe: Annotated[str | None, Query(pattern=r"^CWE-\d{1,5}$")] = None,
    vendor: Annotated[str | None, Query(min_length=1, max_length=100)] = None,
    product: Annotated[str | None, Query(min_length=1, max_length=100)] = None,
    in_kev: bool | None = None,
    published_from: date | None = None,
    published_to: date | None = None,
    include_rejected: bool = False,
    sort: Literal["relevance", "published", "cvss"] = "relevance",
    page: PageQuery = 1,
    page_size: PageSizeQuery = 20,
) -> Page[VulnerabilitySummary]:
    """Full-text search with filters.

    ``q`` accepts a CVE ID (exact match), a CVE prefix such as ``CVE-2024-3``, or
    free text, which is matched with PostgreSQL ``websearch_to_tsquery``, so quoted
    phrases, ``OR`` and ``-term`` work.
    """
    if min_cvss is not None and max_cvss is not None and min_cvss > max_cvss:
        raise AppError("min_cvss must not exceed max_cvss.", status_code=422, code="invalid_range")
    if published_from and published_to and published_from > published_to:
        raise AppError(
            "published_from must not be after published_to.", status_code=422, code="invalid_range"
        )
    filters = VulnerabilityFilters(
        q=q,
        severity=list(severity),
        min_cvss=min_cvss,
        max_cvss=max_cvss,
        cwe=cwe,
        vendor=vendor,
        product=product,
        in_kev=in_kev,
        published_from=published_from,
        published_to=published_to,
        include_rejected=include_rejected,
        sort=sort,
    )
    items, total = search_vulnerabilities(db, filters, page, page_size)
    return Page(
        items=[VulnerabilitySummary(**i) for i in items],
        page=page,
        page_size=page_size,
        total=total,
    )


@router.get(
    "/vulnerabilities/{cve_id}",
    response_model=VulnerabilityDetail,
    responses={status.HTTP_404_NOT_FOUND: {"description": "CVE not stored"}},
)
def detail(cve_id: CveIdPath, db: DbSession) -> VulnerabilityDetail:
    """Everything stored about one CVE, with the provider of every value."""
    found = get_vulnerability_detail(db, cve_id.upper())
    if found is None:
        raise AppError(
            f"{cve_id.upper()} is not in the local dataset. It may exist upstream but has not "
            "been ingested.",
            status_code=status.HTTP_404_NOT_FOUND,
            code="cve_not_found",
        )
    return VulnerabilityDetail.model_validate(found, from_attributes=True)
