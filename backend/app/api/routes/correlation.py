"""Threat-intelligence correlation with explicit rules and evidence paths."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, status

from app.api.deps import CveIdPath, DbSession, TechniqueIdPath
from app.core.exceptions import AppError
from app.core.rate_limit import rate_limit
from app.correlation import service
from app.correlation.rules import rule_dicts
from app.schemas.correlation import (
    CweOverview,
    RuleOut,
    TechniqueCorrelation,
    VulnerabilityCorrelation,
)

router = APIRouter(tags=["correlation"], dependencies=[Depends(rate_limit("search"))])


@router.get("/correlation/rules", response_model=list[RuleOut])
def list_rules() -> list[RuleOut]:
    """Every correlation rule, whether it is authoritative or inferred, and its limits."""
    return [RuleOut(**r) for r in rule_dicts()]


@router.get("/vulnerabilities/{cve_id}/correlations", response_model=VulnerabilityCorrelation)
def vulnerability_correlations(cve_id: CveIdPath, db: DbSession) -> VulnerabilityCorrelation:
    """KEV status, weaknesses, CAPEC patterns, inferred ATT&CK techniques (with the full
    CWE -> CAPEC path), OSV advisories and related CVEs."""
    found = service.correlate_vulnerability(db, cve_id.upper())
    if found is None:
        raise AppError(
            f"{cve_id.upper()} is not in the local dataset.",
            status_code=status.HTTP_404_NOT_FOUND,
            code="cve_not_found",
        )
    return VulnerabilityCorrelation.model_validate(found)


@router.get("/techniques/{technique_id}/vulnerabilities", response_model=TechniqueCorrelation)
def technique_vulnerabilities(
    technique_id: TechniqueIdPath,
    db: DbSession,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> TechniqueCorrelation:
    """CVEs linked to the technique through CWE -> CAPEC mappings (inferred)."""
    found = service.technique_vulnerabilities(db, technique_id.upper(), limit)
    if found is None:
        raise AppError(
            f"Technique {technique_id.upper()} not found.",
            status_code=status.HTTP_404_NOT_FOUND,
            code="technique_not_found",
        )
    return TechniqueCorrelation.model_validate(found)


@router.get("/cwes/{cwe_id}", response_model=CweOverview)
def cwe_overview(
    cwe_id: Annotated[str, Path(pattern=r"^[Cc][Ww][Ee]-\d{1,5}$")], db: DbSession
) -> CweOverview:
    found = service.cwe_overview(db, cwe_id.upper())
    if found is None:
        raise AppError(
            f"{cwe_id.upper()} is not referenced by any stored record.",
            status_code=status.HTTP_404_NOT_FOUND,
            code="cwe_not_found",
        )
    return CweOverview.model_validate(found)
