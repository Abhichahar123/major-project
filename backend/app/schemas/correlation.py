"""Correlation schemas. ``relationship`` is "authoritative" or "inferred" on every link."""

from __future__ import annotations

from datetime import date
from typing import Literal

from pydantic import BaseModel

Relationship = Literal["authoritative", "inferred"]


class RuleOut(BaseModel):
    id: str
    kind: Relationship
    name: str
    description: str
    evidence: str
    limitations: str


class KevLink(BaseModel):
    listed: bool
    date_added: date | None
    known_ransomware_use: str | None
    rule: str
    relationship: Relationship


class WeaknessLink(BaseModel):
    cwe_id: str
    name: str | None
    stated_by: list[str]
    rule: str
    relationship: Relationship


class PatternLink(BaseModel):
    capec_id: str
    name: str
    status: str | None
    url: str | None
    via_cwes: list[str]
    rule: str
    relationship: Relationship


class ChainPath(BaseModel):
    cwe_id: str
    capec_id: str
    capec_name: str


class TechniqueLink(BaseModel):
    technique_id: str
    name: str | None
    tactics: list[str]
    url: str | None
    in_attack_dataset: bool
    paths: list[ChainPath]
    path_count: int
    supporting_cwes: list[str]
    confidence: Literal["low", "medium"]
    via_broad_cwe_only: bool
    rule: str
    relationship: Relationship


class AdvisoryLink(BaseModel):
    id: str
    summary: str | None
    severity: str | None
    url: str
    rule: str
    relationship: Relationship


class RelatedReason(BaseModel):
    rule: str
    shared: str


class RelatedVulnerability(BaseModel):
    cve_id: str
    title: str | None
    severity: str | None
    cvss_base_score: float | None
    in_kev: bool
    reasons: list[RelatedReason]
    relationship: Relationship


class VulnerabilityCorrelation(BaseModel):
    cve_id: str
    record_available: bool
    kev: KevLink
    weaknesses: list[WeaknessLink]
    attack_patterns: list[PatternLink]
    techniques: list[TechniqueLink]
    advisories: list[AdvisoryLink]
    related_vulnerabilities: list[RelatedVulnerability]
    notes: list[str]
    rules: list[RuleOut]


class TechniqueVulnerability(BaseModel):
    cve_id: str
    title: str | None
    severity: str | None
    cvss_base_score: float | None
    in_kev: bool
    paths: list[ChainPath]
    path_count: int
    rule: str
    relationship: Relationship


class CapecRef(BaseModel):
    capec_id: str
    name: str


class TechniqueCorrelation(BaseModel):
    technique_id: str
    name: str
    capec_patterns: list[CapecRef]
    total: int
    vulnerabilities: list[TechniqueVulnerability]
    rules: list[RuleOut]


class CweOverview(BaseModel):
    cwe_id: str
    name: str | None
    url: str
    vulnerability_count: int
    kev_count: int
    attack_patterns: list[PatternLink]
    techniques: list[TechniqueLink]
    notes: list[str]
    rules: list[RuleOut]
