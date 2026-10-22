"""Queries for vulnerabilities, KEV entries, ATT&CK techniques, sources and statistics.

All filtering uses SQLAlchemy expressions with bound parameters. User text used in
LIKE patterns is escaped, so ``%`` and ``_`` match literally.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Literal

from sqlalchemy import Select, and_, exists, func, null, or_, select
from sqlalchemy.orm import Session

from app.db.models import (
    Advisory,
    AdvisoryPackage,
    AffectedProduct,
    AttackTechnique,
    CapecPattern,
    ChunkEmbedding,
    CvssMetric,
    CweEntry,
    DocumentChunk,
    IngestionError,
    IngestionJob,
    KevEntry,
    Source,
    SourceRecord,
    Vulnerability,
    VulnerabilityCwe,
    VulnReference,
)
from app.ingestion.normalize import CVE_ID_RE

SEVERITY_RULE = (
    "Display severity is chosen from the stored CVSS scores: CNA first, then NVD primary, "
    "then CISA-ADP; within a provider CVSS v3.1 > v3.0 > v4.0 > v2.0. All scores are listed "
    "under 'cvss' with their provider."
)
SNIPPET_LENGTH = 300
_CVE_PREFIX = re.compile(r"^CVE-\d{4}(-\d{0,7})?$", re.IGNORECASE)


def escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _contains(column: Any, text: str) -> Any:
    return column.ilike(f"%{escape_like(text)}%", escape="\\")


def _snippet(text: str | None) -> str | None:
    if not text:
        return None
    return text if len(text) <= SNIPPET_LENGTH else text[: SNIPPET_LENGTH - 1].rstrip() + "…"


# ----------------------------------------------------------------- vulnerabilities


@dataclass
class VulnerabilityFilters:
    q: str | None = None
    severity: list[str] = field(default_factory=list)
    min_cvss: float | None = None
    max_cvss: float | None = None
    cwe: str | None = None
    vendor: str | None = None
    product: str | None = None
    in_kev: bool | None = None
    published_from: date | None = None
    published_to: date | None = None
    include_rejected: bool = False
    sort: Literal["relevance", "published", "cvss"] = "relevance"


def _vulnerability_query(f: VulnerabilityFilters) -> tuple[Select[Any], Any]:
    rank: Any = None
    stmt = select(Vulnerability)
    if not f.include_rejected:
        stmt = stmt.where(Vulnerability.state == "PUBLISHED")
    q = (f.q or "").strip()
    if q:
        upper = q.upper()
        if CVE_ID_RE.match(upper):
            stmt = stmt.where(Vulnerability.cve_id == upper)
        elif _CVE_PREFIX.match(upper):
            stmt = stmt.where(Vulnerability.cve_id.like(f"{escape_like(upper)}%", escape="\\"))
        else:
            tsquery = func.websearch_to_tsquery("english", q)
            stmt = stmt.where(Vulnerability.search_tsv.op("@@")(tsquery))
            rank = func.ts_rank_cd(Vulnerability.search_tsv, tsquery)
    if f.severity:
        stmt = stmt.where(Vulnerability.severity.in_(f.severity))
    if f.min_cvss is not None:
        stmt = stmt.where(Vulnerability.cvss_base_score >= f.min_cvss)
    if f.max_cvss is not None:
        stmt = stmt.where(Vulnerability.cvss_base_score <= f.max_cvss)
    if f.cwe:
        stmt = stmt.where(
            exists().where(
                VulnerabilityCwe.vulnerability_id == Vulnerability.id,
                VulnerabilityCwe.cwe_id == f.cwe,
            )
        )
    if f.vendor or f.product:
        conditions = [AffectedProduct.vulnerability_id == Vulnerability.id]
        if f.vendor:
            conditions.append(_contains(AffectedProduct.vendor, f.vendor))
        if f.product:
            conditions.append(
                or_(
                    _contains(AffectedProduct.product, f.product),
                    _contains(AffectedProduct.package_name, f.product),
                )
            )
        stmt = stmt.where(exists().where(and_(*conditions)))
    kev_exists = exists().where(KevEntry.cve_id == Vulnerability.cve_id)
    if f.in_kev is True:
        stmt = stmt.where(kev_exists)
    elif f.in_kev is False:
        stmt = stmt.where(~kev_exists)
    if f.published_from:
        stmt = stmt.where(func.date(Vulnerability.published_at) >= f.published_from)
    if f.published_to:
        stmt = stmt.where(func.date(Vulnerability.published_at) <= f.published_to)
    return stmt, rank


def search_vulnerabilities(
    session: Session, f: VulnerabilityFilters, page: int, page_size: int
) -> tuple[list[dict[str, Any]], int]:
    stmt, rank = _vulnerability_query(f)
    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0

    if rank is not None and f.sort == "relevance":
        ordered = stmt.add_columns(rank.label("rank")).order_by(
            rank.desc(), Vulnerability.published_at.desc().nulls_last(), Vulnerability.cve_id
        )
    else:
        rank_column = rank.label("rank") if rank is not None else null().label("rank")
        key = Vulnerability.cvss_base_score if f.sort == "cvss" else Vulnerability.published_at
        ordered = stmt.add_columns(rank_column).order_by(
            key.desc().nulls_last(), Vulnerability.cve_id
        )
    rows = session.execute(ordered.limit(page_size).offset((page - 1) * page_size)).all()
    vulns = [row[0] for row in rows]
    ranks = [row[1] for row in rows]
    ids = [v.id for v in vulns]
    cve_ids = [v.cve_id for v in vulns]

    kev_dates = (
        dict(
            session.execute(
                select(KevEntry.cve_id, KevEntry.date_added).where(KevEntry.cve_id.in_(cve_ids))
            ).all()
        )
        if cve_ids
        else {}
    )
    cwes: dict[int, set[str]] = {}
    if ids:
        for vid, cwe in session.execute(
            select(VulnerabilityCwe.vulnerability_id, VulnerabilityCwe.cwe_id).where(
                VulnerabilityCwe.vulnerability_id.in_(ids)
            )
        ):
            cwes.setdefault(vid, set()).add(cwe)

    items = [
        {
            "cve_id": v.cve_id,
            "state": v.state,
            "title": v.title,
            "description_snippet": _snippet(v.description),
            "severity": v.severity,
            "cvss_base_score": v.cvss_base_score,
            "cvss_version": v.cvss_version,
            "published_at": v.published_at,
            "in_kev": v.cve_id in kev_dates,
            "kev_date_added": kev_dates.get(v.cve_id),
            "cwes": sorted(cwes.get(v.id, set())),
            "rank": round(float(r), 4) if r is not None else None,
        }
        for v, r in zip(vulns, ranks, strict=True)
    ]
    return items, total


def fixed_versions(ranges: list[dict[str, Any]]) -> list[str]:
    return sorted({e["fixed"] for r in ranges for e in r.get("events", []) if "fixed" in e})


def advisories_for_cves(session: Session, cve_ids: list[str]) -> dict[str, list[dict[str, Any]]]:
    """OSV advisories aliasing each CVE, with affected packages and fixed versions."""
    if not cve_ids:
        return {}
    advisories = session.scalars(
        select(Advisory).where(Advisory.cve_ids.overlap(cve_ids)).order_by(Advisory.id)
    ).all()
    packages: dict[str, list[AdvisoryPackage]] = {}
    if advisories:
        for pkg in session.scalars(
            select(AdvisoryPackage).where(
                AdvisoryPackage.advisory_id.in_([a.id for a in advisories])
            )
        ):
            packages.setdefault(pkg.advisory_id, []).append(pkg)
    out: dict[str, list[dict[str, Any]]] = {}
    for adv in advisories:
        # OSV may list the same package once per affected range; merge them per package.
        merged: dict[tuple[str, str], dict[str, Any]] = {}
        for pkg in packages.get(adv.id, []):
            entry = merged.setdefault(
                (pkg.ecosystem, pkg.normalized_name),
                {"ecosystem": pkg.ecosystem, "name": pkg.name, "ranges": []},
            )
            entry["ranges"].extend(pkg.ranges)
        item = {
            "id": adv.id,
            "summary": adv.summary,
            "severity": adv.severity,
            "url": adv.source_url,
            "packages": [
                {**entry, "fixed_versions": fixed_versions(entry["ranges"])}
                for entry in merged.values()
            ],
        }
        for cve in adv.cve_ids:
            if cve in cve_ids:
                out.setdefault(cve, []).append(item)
    return out


def get_vulnerability_detail(session: Session, cve_id: str) -> dict[str, Any] | None:
    vuln = session.scalar(select(Vulnerability).where(Vulnerability.cve_id == cve_id))
    kev = session.get(KevEntry, cve_id)
    if vuln is None:
        if kev is None:
            return None
        # Listed by CISA KEV, but the CVE record has not been ingested yet.
        return {
            "cve_id": cve_id,
            "record_available": False,
            "state": "UNKNOWN",
            "title": None,
            "description": None,
            "assigner": None,
            "published_at": None,
            "source_updated_at": None,
            "severity": None,
            "cvss_base_score": None,
            "cvss_version": None,
            "cvss_provider": None,
            "severity_rule": SEVERITY_RULE,
            "cvss": [],
            "cwes": [],
            "affected": [],
            "references": [],
            "kev": kev,
            "advisories": advisories_for_cves(session, [cve_id]).get(cve_id, []),
            "provenance": _provenance(session, cve_id),
        }

    cvss = session.scalars(
        select(CvssMetric)
        .where(CvssMetric.vulnerability_id == vuln.id)
        .order_by(CvssMetric.provider_rank, CvssMetric.provider, CvssMetric.version.desc())
    ).all()
    cwe_rows = session.execute(
        select(VulnerabilityCwe.cwe_id, VulnerabilityCwe.provider, CweEntry.name)
        .join(CweEntry, CweEntry.cwe_id == VulnerabilityCwe.cwe_id)
        .where(VulnerabilityCwe.vulnerability_id == vuln.id)
    ).all()
    cwes: dict[str, dict[str, Any]] = {}
    for cwe_id, provider, name in cwe_rows:
        entry = cwes.setdefault(cwe_id, {"cwe_id": cwe_id, "name": name, "providers": []})
        if provider not in entry["providers"]:
            entry["providers"].append(provider)
    affected = session.scalars(
        select(AffectedProduct)
        .where(AffectedProduct.vulnerability_id == vuln.id)
        .order_by(AffectedProduct.ingest_source, AffectedProduct.id)
    ).all()
    references = session.scalars(
        select(VulnReference)
        .where(VulnReference.vulnerability_id == vuln.id)
        .order_by(VulnReference.id)
    ).all()
    return {
        "cve_id": vuln.cve_id,
        "record_available": True,
        "state": vuln.state,
        "title": vuln.title,
        "description": vuln.description,
        "assigner": vuln.assigner,
        "published_at": vuln.published_at,
        "source_updated_at": vuln.source_updated_at,
        "severity": vuln.severity,
        "cvss_base_score": vuln.cvss_base_score,
        "cvss_version": vuln.cvss_version,
        "cvss_provider": vuln.cvss_provider,
        "severity_rule": SEVERITY_RULE,
        "cvss": cvss,
        "cwes": sorted(cwes.values(), key=lambda c: c["cwe_id"]),
        "affected": affected,
        "references": references,
        "kev": kev,
        "advisories": advisories_for_cves(session, [cve_id]).get(cve_id, []),
        "provenance": _provenance(session, cve_id),
    }


def _provenance(session: Session, record_key: str) -> list[dict[str, Any]]:
    rows = session.execute(
        select(
            Source.code,
            Source.name,
            SourceRecord.source_url,
            SourceRecord.last_fetched_at,
            SourceRecord.last_changed_at,
        )
        .join(Source, Source.id == SourceRecord.source_id)
        .where(SourceRecord.record_key == record_key)
        .order_by(Source.id)
    ).all()
    return [
        {
            "source": code,
            "source_name": name,
            "record_url": url,
            "last_fetched_at": fetched,
            "last_changed_at": changed,
        }
        for code, name, url, fetched, changed in rows
    ]


# --------------------------------------------------------------------------- KEV


@dataclass
class KevFilters:
    q: str | None = None
    vendor: str | None = None
    ransomware: Literal["Known", "Unknown"] | None = None
    date_added_from: date | None = None
    date_added_to: date | None = None
    cwe: str | None = None


def list_kev(
    session: Session, f: KevFilters, page: int, page_size: int
) -> tuple[list[dict[str, Any]], int]:
    stmt = select(
        KevEntry, Vulnerability.severity, Vulnerability.cvss_base_score, Vulnerability.id
    ).outerjoin(Vulnerability, Vulnerability.cve_id == KevEntry.cve_id)
    if f.q:
        q = f.q.strip()
        if CVE_ID_RE.match(q.upper()):
            stmt = stmt.where(KevEntry.cve_id == q.upper())
        else:
            stmt = stmt.where(
                or_(
                    _contains(KevEntry.vendor_project, q),
                    _contains(KevEntry.product, q),
                    _contains(KevEntry.vulnerability_name, q),
                )
            )
    if f.vendor:
        stmt = stmt.where(_contains(KevEntry.vendor_project, f.vendor))
    if f.ransomware:
        stmt = stmt.where(KevEntry.known_ransomware_use == f.ransomware)
    if f.date_added_from:
        stmt = stmt.where(KevEntry.date_added >= f.date_added_from)
    if f.date_added_to:
        stmt = stmt.where(KevEntry.date_added <= f.date_added_to)
    if f.cwe:
        stmt = stmt.where(KevEntry.cwes.contains([f.cwe]))
    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = session.execute(
        stmt.order_by(KevEntry.date_added.desc(), KevEntry.cve_id.desc())
        .limit(page_size)
        .offset((page - 1) * page_size)
    ).all()
    return [_kev_item(kev, sev, score, vid) for kev, sev, score, vid in rows], total


def _kev_item(
    kev: KevEntry, severity: str | None, score: float | None, vuln_id: int | None
) -> dict[str, Any]:
    return {
        "cve_id": kev.cve_id,
        "vendor_project": kev.vendor_project,
        "product": kev.product,
        "vulnerability_name": kev.vulnerability_name,
        "date_added": kev.date_added,
        "due_date": kev.due_date,
        "known_ransomware_use": kev.known_ransomware_use,
        "cwes": kev.cwes,
        "has_cve_record": vuln_id is not None,
        "severity": severity,
        "cvss_base_score": score,
    }


# ---------------------------------------------------------------------- techniques


def _technique_tsv() -> Any:
    # Must match the expression of ix_attack_techniques_search to use the index.
    return func.to_tsvector(
        "english", AttackTechnique.name + " " + func.coalesce(AttackTechnique.description, "")
    )


def list_techniques(
    session: Session,
    q: str | None,
    tactic: str | None,
    platform: str | None,
    include_deprecated: bool,
    page: int,
    page_size: int,
) -> tuple[list[AttackTechnique], int]:
    stmt = select(AttackTechnique)
    if not include_deprecated:
        stmt = stmt.where(~AttackTechnique.deprecated, ~AttackTechnique.revoked)
    order: list[Any] = [AttackTechnique.technique_id]
    if q:
        q = q.strip()
        if re.match(r"^T\d{4}(\.\d{3})?$", q.upper()):
            stmt = stmt.where(AttackTechnique.technique_id == q.upper())
        else:
            tsquery = func.websearch_to_tsquery("english", q)
            stmt = stmt.where(
                or_(_technique_tsv().op("@@")(tsquery), _contains(AttackTechnique.name, q))
            )
            order = [func.ts_rank_cd(_technique_tsv(), tsquery).desc(), *order]
    if tactic:
        stmt = stmt.where(AttackTechnique.tactics.contains([tactic]))
    if platform:
        stmt = stmt.where(AttackTechnique.platforms.contains([platform]))
    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    items = session.scalars(stmt.order_by(*order).limit(page_size).offset((page - 1) * page_size))
    return list(items), total


def get_technique(session: Session, technique_id: str) -> dict[str, Any] | None:
    tech = session.scalar(
        select(AttackTechnique).where(AttackTechnique.technique_id == technique_id)
    )
    if tech is None:
        return None
    subs = session.scalars(
        select(AttackTechnique)
        .where(AttackTechnique.parent_technique_id == technique_id, ~AttackTechnique.revoked)
        .order_by(AttackTechnique.technique_id)
    ).all()
    return {
        **{
            c: getattr(tech, c)
            for c in (
                "technique_id",
                "name",
                "tactics",
                "platforms",
                "is_subtechnique",
                "deprecated",
                "revoked",
                "url",
                "description",
                "parent_technique_id",
                "attack_version",
            )
        },
        "subtechniques": subs,
    }


# ------------------------------------------------------------------------ sources


def _latest_job(job: IngestionJob | None) -> dict[str, Any] | None:
    if job is None:
        return None
    return {
        c: getattr(job, c)
        for c in (
            "id",
            "status",
            "trigger",
            "created_at",
            "finished_at",
            "records_fetched",
            "records_inserted",
            "records_updated",
            "records_unchanged",
            "records_failed",
        )
    }


def list_sources(session: Session) -> list[dict[str, Any]]:
    counts = dict(
        session.execute(
            select(SourceRecord.source_id, func.count()).group_by(SourceRecord.source_id)
        ).all()
    )
    latest_ids = select(func.max(IngestionJob.id)).group_by(IngestionJob.source_id)
    latest = {
        j.source_id: j
        for j in session.scalars(select(IngestionJob).where(IngestionJob.id.in_(latest_ids)))
    }
    out = []
    for src in session.scalars(select(Source).order_by(Source.id)):
        out.append(
            {
                "code": src.code,
                "name": src.name,
                "url": src.url,
                "description": src.description,
                "last_success_at": src.last_success_at,
                "tracked_records": counts.get(src.id, 0),
                "latest_job": _latest_job(latest.get(src.id)),
            }
        )
    return out


def _job_dict(job: IngestionJob, source_code: str) -> dict[str, Any]:
    base = _latest_job(job) or {}
    return {
        **base,
        "source": source_code,
        "params": job.params,
        "started_at": job.started_at,
        "error_summary": job.error_summary,
        "details": job.details,
    }


def list_jobs(
    session: Session, source: str | None, status: str | None, page: int, page_size: int
) -> tuple[list[dict[str, Any]], int]:
    stmt = select(IngestionJob, Source.code).join(Source, Source.id == IngestionJob.source_id)
    if source:
        stmt = stmt.where(Source.code == source)
    if status:
        stmt = stmt.where(IngestionJob.status == status)
    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = session.execute(
        stmt.order_by(IngestionJob.id.desc()).limit(page_size).offset((page - 1) * page_size)
    ).all()
    return [_job_dict(job, code) for job, code in rows], total


def get_job(session: Session, job_id: int, include_errors: bool) -> dict[str, Any] | None:
    row = session.execute(
        select(IngestionJob, Source.code)
        .join(Source, Source.id == IngestionJob.source_id)
        .where(IngestionJob.id == job_id)
    ).first()
    if row is None:
        return None
    job, code = row
    errors = (
        session.scalars(
            select(IngestionError)
            .where(IngestionError.job_id == job_id)
            .order_by(IngestionError.id)
            .limit(100)
        ).all()
        if include_errors
        else []
    )
    return {**_job_dict(job, code), "errors": errors}


# -------------------------------------------------------------------------- stats


def stats(session: Session) -> dict[str, Any]:
    def count(stmt: Any) -> int:
        return session.scalar(stmt) or 0

    severity_key = func.coalesce(Vulnerability.severity, "UNSCORED")
    by_severity = session.execute(
        select(severity_key, func.count())
        .where(Vulnerability.state == "PUBLISHED")
        .group_by(severity_key)
        .order_by(func.count().desc())
    ).all()
    top_cwes = session.execute(
        select(
            VulnerabilityCwe.cwe_id,
            CweEntry.name,
            func.count(func.distinct(VulnerabilityCwe.vulnerability_id)),
        )
        .join(CweEntry, CweEntry.cwe_id == VulnerabilityCwe.cwe_id)
        .group_by(VulnerabilityCwe.cwe_id, CweEntry.name)
        .order_by(func.count(func.distinct(VulnerabilityCwe.vulnerability_id)).desc())
        .limit(10)
    ).all()
    recent, _ = list_kev(session, KevFilters(), 1, 5)
    return {
        "vulnerabilities": count(select(func.count()).select_from(Vulnerability)),
        "kev_entries": count(select(func.count()).select_from(KevEntry)),
        "kev_with_cve_record": count(
            select(func.count())
            .select_from(KevEntry)
            .where(exists().where(Vulnerability.cve_id == KevEntry.cve_id))
        ),
        "attack_techniques": count(
            select(func.count())
            .select_from(AttackTechnique)
            .where(~AttackTechnique.revoked, ~AttackTechnique.deprecated)
        ),
        "capec_patterns": count(select(func.count()).select_from(CapecPattern)),
        "advisories": count(select(func.count()).select_from(Advisory)),
        "document_chunks": count(select(func.count()).select_from(DocumentChunk)),
        "embedded_chunks": count(select(func.count(func.distinct(ChunkEmbedding.chunk_id)))),
        "by_severity": [{"key": k, "count": c} for k, c in by_severity],
        "top_cwes": [{"key": k, "label": n, "count": c} for k, n, c in top_cwes],
        "recent_kev": recent,
    }
