"""Vulnerability, KEV, technique, source and statistics schemas."""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel


class KevSummary(ORMModel):
    date_added: date
    due_date: date | None
    known_ransomware_use: str
    required_action: str


class VulnerabilitySummary(BaseModel):
    cve_id: str
    state: str
    title: str | None
    description_snippet: str | None
    severity: str | None
    cvss_base_score: float | None
    cvss_version: str | None
    published_at: datetime | None
    in_kev: bool
    kev_date_added: date | None
    cwes: list[str]
    rank: float | None = Field(default=None, description="Full-text relevance, when searching")


class CvssOut(ORMModel):
    provider: str
    ingest_source: str
    version: str
    base_score: float
    base_severity: str | None
    vector: str | None


class CweOut(BaseModel):
    cwe_id: str
    name: str | None
    providers: list[str]


class AffectedOut(ORMModel):
    provider: str
    ingest_source: str
    vendor: str | None
    product: str | None
    package_name: str | None
    ecosystem: str | None
    default_status: str | None
    versions: list[dict[str, Any]]
    cpes: list[str]


class ReferenceOut(ORMModel):
    url: str
    name: str | None
    tags: list[str]


class KevOut(ORMModel):
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    short_description: str
    required_action: str
    notes: str | None
    date_added: date
    due_date: date | None
    known_ransomware_use: str
    cwes: list[str]
    catalog_version: str | None


class AdvisoryPackageOut(BaseModel):
    ecosystem: str
    name: str
    fixed_versions: list[str]
    ranges: list[dict[str, Any]]


class AdvisoryOut(BaseModel):
    id: str
    summary: str | None
    severity: str | None
    url: str
    packages: list[AdvisoryPackageOut]


class ProvenanceOut(BaseModel):
    source: str
    source_name: str
    record_url: str | None
    last_fetched_at: datetime
    last_changed_at: datetime


class VulnerabilityDetail(BaseModel):
    cve_id: str
    record_available: bool = Field(
        description="False when the CVE is listed by CISA KEV but its CVE record is not stored"
    )
    state: str
    title: str | None
    description: str | None
    assigner: str | None
    published_at: datetime | None
    source_updated_at: datetime | None
    severity: str | None
    cvss_base_score: float | None
    cvss_version: str | None
    cvss_provider: str | None
    severity_rule: str
    cvss: list[CvssOut]
    cwes: list[CweOut]
    affected: list[AffectedOut]
    references: list[ReferenceOut]
    kev: KevOut | None
    advisories: list[AdvisoryOut]
    provenance: list[ProvenanceOut]


class KevListItem(BaseModel):
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: date
    due_date: date | None
    known_ransomware_use: str
    cwes: list[str]
    has_cve_record: bool
    severity: str | None
    cvss_base_score: float | None


class TechniqueSummary(ORMModel):
    technique_id: str
    name: str
    tactics: list[str]
    platforms: list[str]
    is_subtechnique: bool
    deprecated: bool
    revoked: bool
    url: str | None


class TechniqueDetail(TechniqueSummary):
    description: str | None
    parent_technique_id: str | None
    attack_version: str | None
    subtechniques: list[TechniqueSummary]


class LatestJob(BaseModel):
    id: int
    status: str
    trigger: str
    created_at: datetime
    finished_at: datetime | None
    records_fetched: int
    records_inserted: int
    records_updated: int
    records_unchanged: int
    records_failed: int


class SourceStatus(BaseModel):
    code: str
    name: str
    url: str
    description: str | None
    last_success_at: datetime | None
    tracked_records: int
    latest_job: LatestJob | None


class JobOut(LatestJob):
    source: str
    params: dict[str, Any]
    started_at: datetime | None
    error_summary: str | None
    details: dict[str, Any] | None


class JobErrorOut(ORMModel):
    record_key: str | None
    stage: str
    message: str
    created_at: datetime


class JobDetail(JobOut):
    errors: list[JobErrorOut]


class JobCreate(BaseModel):
    source: str = Field(pattern=r"^[a-z0-9]{2,32}$")
    params: dict[str, Any] = Field(default_factory=dict)


class JobAccepted(BaseModel):
    job_id: int
    source: str
    status: str
    status_url: str


class CountItem(BaseModel):
    key: str
    label: str | None = None
    count: int


class Stats(BaseModel):
    vulnerabilities: int
    kev_entries: int
    kev_with_cve_record: int
    attack_techniques: int
    capec_patterns: int
    advisories: int
    document_chunks: int
    embedded_chunks: int
    by_severity: list[CountItem]
    top_cwes: list[CountItem]
    recent_kev: list[KevListItem]
