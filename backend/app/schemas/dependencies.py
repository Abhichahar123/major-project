"""Dependency analysis response schema."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class FindingOut(BaseModel):
    package: str
    ecosystem: str
    version: str | None
    specifier: str | None
    location: str
    confidence: Literal["confirmed", "uncertain"] = Field(
        description="confirmed: exact package and pinned version inside an affected range; "
        "uncertain: name-only match, unpinned or unparsable version"
    )
    reason: str
    advisory_id: str | None
    cve_ids: list[str]
    severity: str | None
    summary: str | None
    fixed_versions: list[str]
    in_kev: bool
    source: str
    references: list[str]


class DependencyReport(BaseModel):
    filename: str
    sha256: str
    format: str
    ecosystem: str
    dependency_count: int
    checked_count: int
    unpinned_count: int
    vulnerable_packages: int
    findings: list[FindingOut]
    not_checked: list[dict[str, str]]
    warnings: list[str]
    summary: dict[str, Any]
    sources: list[str]
