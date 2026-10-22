"""Idempotent persistence of normalized records.

All writes are upserts keyed on natural identifiers. ``record_seen`` compares a content
hash with the stored provenance row, so callers can skip records that have not changed
since the last run.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.db.models import (
    Advisory,
    AdvisoryPackage,
    AffectedProduct,
    AttackTechnique,
    CapecAttackMapping,
    CapecCweMapping,
    CapecPattern,
    CvssMetric,
    CweEntry,
    KevEntry,
    Source,
    SourceRecord,
    Vulnerability,
    VulnerabilityCwe,
    VulnReference,
)
from app.ingestion.normalize import (
    CvssScore,
    NormalizedAdvisory,
    NormalizedCapec,
    NormalizedKev,
    NormalizedTechnique,
    NormalizedVulnerability,
    select_display_cvss,
)


class Change(StrEnum):
    INSERTED = "inserted"
    UPDATED = "updated"
    UNCHANGED = "unchanged"
    SKIPPED = "skipped"  # valid record intentionally not stored (e.g. withdrawn)


def get_source(session: Session, code: str) -> Source:
    source = session.scalar(select(Source).where(Source.code == code))
    if source is None:
        raise LookupError(f"unknown source {code!r}; run database migrations")
    return source


def record_seen(
    session: Session,
    *,
    source_id: int,
    record_key: str,
    digest: str,
    job_id: int | None,
    source_url: str | None = None,
) -> bool:
    """Upsert provenance and return True if the content changed (or is new)."""
    now = datetime.now(UTC)
    existing = session.scalar(
        select(SourceRecord).where(
            SourceRecord.source_id == source_id, SourceRecord.record_key == record_key
        )
    )
    if existing is None:
        session.add(
            SourceRecord(
                source_id=source_id,
                record_key=record_key,
                source_url=source_url,
                content_hash=digest,
                last_fetched_at=now,
                last_changed_at=now,
                last_job_id=job_id,
            )
        )
        return True
    existing.last_fetched_at = now
    existing.last_job_id = job_id
    if source_url:
        existing.source_url = source_url
    if existing.content_hash == digest:
        return False
    existing.content_hash = digest
    existing.last_changed_at = now
    return True


def _ensure_cwes(session: Session, cwes: list[tuple[str, str, str | None]]) -> None:
    names: dict[str, str | None] = {}
    for cwe_id, _, name in cwes:
        names[cwe_id] = names.get(cwe_id) or name
    if not names:
        return
    stmt = insert(CweEntry).values([{"cwe_id": k, "name": v} for k, v in names.items()])
    stmt = stmt.on_conflict_do_update(
        index_elements=[CweEntry.cwe_id],
        set_={"name": func.coalesce(CweEntry.name, stmt.excluded.name)},
    )
    session.execute(stmt)


def ensure_cwe_ids(session: Session, cwe_ids: list[str]) -> None:
    _ensure_cwes(session, [(c, "", None) for c in cwe_ids])


def refresh_display_severity(session: Session, vulnerability_id: int) -> None:
    rows = session.scalars(
        select(CvssMetric).where(CvssMetric.vulnerability_id == vulnerability_id)
    ).all()
    best = select_display_cvss(
        [
            CvssScore(
                r.provider, r.version, r.base_score, r.base_severity, r.vector, r.provider_rank
            )
            for r in rows
        ]
    )
    session.execute(
        update(Vulnerability)
        .where(Vulnerability.id == vulnerability_id)
        .values(
            severity=best.base_severity if best else None,
            cvss_base_score=best.base_score if best else None,
            cvss_version=best.version if best else None,
            cvss_provider=best.provider if best else None,
        )
    )


def upsert_vulnerability(
    session: Session, vuln: NormalizedVulnerability, ingest_source: str
) -> Change:
    """Write a vulnerability and replace this source's child rows.

    The CVE Program record (``cve5``) is authoritative for core fields. Other sources
    (NVD) only fill fields that are still empty.
    """
    existing_id = session.scalar(
        select(Vulnerability.id).where(Vulnerability.cve_id == vuln.cve_id)
    )
    core = {
        "cve_id": vuln.cve_id,
        "state": vuln.state,
        "title": vuln.title,
        "description": vuln.description,
        "assigner": vuln.assigner,
        "published_at": vuln.published_at,
        "source_updated_at": vuln.source_updated_at,
    }
    stmt = insert(Vulnerability).values(**core)
    if ingest_source == "cve5":
        set_ = {k: getattr(stmt.excluded, k) for k in core if k != "cve_id"}
    else:
        set_ = {
            k: func.coalesce(getattr(Vulnerability, k), getattr(stmt.excluded, k))
            for k in core
            if k not in {"cve_id", "state"}
        }
    set_["updated_at"] = func.now()
    stmt = stmt.on_conflict_do_update(index_elements=[Vulnerability.cve_id], set_=set_)
    vuln_id = session.execute(stmt.returning(Vulnerability.id)).scalar_one()

    for model in (CvssMetric, VulnerabilityCwe, AffectedProduct, VulnReference):
        session.execute(
            delete(model).where(
                model.vulnerability_id == vuln_id,
                model.ingest_source == ingest_source,
            )
        )

    seen_versions: set[tuple[str, str]] = set()
    for score in vuln.cvss:
        key = (score.provider, score.version)
        if key in seen_versions:  # one score per provider and CVSS version
            continue
        seen_versions.add(key)
        session.add(
            CvssMetric(
                vulnerability_id=vuln_id,
                ingest_source=ingest_source,
                provider=score.provider,
                version=score.version,
                vector=score.vector,
                base_score=score.base_score,
                base_severity=score.base_severity,
                provider_rank=score.provider_rank,
            )
        )

    _ensure_cwes(session, vuln.cwes)
    for cwe_id, provider, _ in vuln.cwes:
        session.add(
            VulnerabilityCwe(
                vulnerability_id=vuln_id,
                cwe_id=cwe_id,
                ingest_source=ingest_source,
                provider=provider,
            )
        )

    for entry in vuln.affected:
        session.add(
            AffectedProduct(
                vulnerability_id=vuln_id,
                ingest_source=ingest_source,
                provider=entry.provider,
                vendor=entry.vendor,
                product=entry.product,
                package_name=entry.package_name,
                collection_url=entry.collection_url,
                ecosystem=entry.ecosystem,
                default_status=entry.default_status,
                cpes=entry.cpes,
                versions=entry.versions,
            )
        )

    # A URL may already be stored by another source; keep the first and skip duplicates.
    existing_urls = set(
        session.scalars(select(VulnReference.url).where(VulnReference.vulnerability_id == vuln_id))
    )
    for ref in vuln.references:
        if ref.url in existing_urls:
            continue
        existing_urls.add(ref.url)
        session.add(
            VulnReference(
                vulnerability_id=vuln_id,
                url=ref.url,
                ingest_source=ingest_source,
                name=ref.name,
                tags=ref.tags,
            )
        )

    session.flush()
    refresh_display_severity(session, vuln_id)
    return Change.UPDATED if existing_id else Change.INSERTED


def upsert_kev(session: Session, kev: NormalizedKev, catalog_version: str | None) -> Change:
    exists = session.get(KevEntry, kev.cve_id) is not None
    values = {
        "cve_id": kev.cve_id,
        "vendor_project": kev.vendor_project,
        "product": kev.product,
        "vulnerability_name": kev.vulnerability_name,
        "short_description": kev.short_description,
        "required_action": kev.required_action,
        "notes": kev.notes,
        "date_added": kev.date_added,
        "due_date": kev.due_date,
        "known_ransomware_use": kev.known_ransomware_use,
        "cwes": kev.cwes,
        "catalog_version": catalog_version,
    }
    stmt = insert(KevEntry).values(**values)
    stmt = stmt.on_conflict_do_update(
        index_elements=[KevEntry.cve_id],
        set_={
            **{k: getattr(stmt.excluded, k) for k in values if k != "cve_id"},
            "updated_at": func.now(),
        },
    )
    session.execute(stmt)
    ensure_cwe_ids(session, kev.cwes)
    return Change.UPDATED if exists else Change.INSERTED


def remove_kev_entries_not_in(session: Session, keep: set[str]) -> list[str]:
    """Delete catalog entries CISA no longer lists; returns the removed CVE IDs."""
    current = set(session.scalars(select(KevEntry.cve_id)))
    removed = sorted(current - keep)
    if removed:
        session.execute(delete(KevEntry).where(KevEntry.cve_id.in_(removed)))
    return removed


def upsert_technique(
    session: Session, tech: NormalizedTechnique, attack_version: str | None
) -> Change:
    exists = session.scalar(
        select(AttackTechnique.id).where(AttackTechnique.stix_id == tech.stix_id)
    )
    values = {
        "stix_id": tech.stix_id,
        "technique_id": tech.technique_id,
        "name": tech.name,
        "description": tech.description,
        "tactics": tech.tactics,
        "platforms": tech.platforms,
        "is_subtechnique": tech.is_subtechnique,
        "parent_technique_id": tech.parent_technique_id,
        "url": tech.url,
        "deprecated": tech.deprecated,
        "revoked": tech.revoked,
        "attack_version": attack_version,
        "source_modified_at": tech.source_modified_at,
    }
    stmt = insert(AttackTechnique).values(**values)
    stmt = stmt.on_conflict_do_update(
        index_elements=[AttackTechnique.stix_id],
        set_={
            **{k: getattr(stmt.excluded, k) for k in values if k != "stix_id"},
            "updated_at": func.now(),
        },
    )
    session.execute(stmt)
    return Change.UPDATED if exists else Change.INSERTED


def upsert_capec(session: Session, pattern: NormalizedCapec) -> Change:
    exists = session.get(CapecPattern, pattern.capec_id) is not None
    values = {
        "capec_id": pattern.capec_id,
        "stix_id": pattern.stix_id,
        "name": pattern.name,
        "description": pattern.description,
        "url": pattern.url,
        "status": pattern.status,
        "abstraction": pattern.abstraction,
        "likelihood": pattern.likelihood,
        "typical_severity": pattern.typical_severity,
    }
    stmt = insert(CapecPattern).values(**values)
    stmt = stmt.on_conflict_do_update(
        index_elements=[CapecPattern.capec_id],
        set_={
            **{k: getattr(stmt.excluded, k) for k in values if k != "capec_id"},
            "updated_at": func.now(),
        },
    )
    session.execute(stmt)
    session.execute(delete(CapecCweMapping).where(CapecCweMapping.capec_id == pattern.capec_id))
    session.execute(
        delete(CapecAttackMapping).where(CapecAttackMapping.capec_id == pattern.capec_id)
    )
    for cwe_id in pattern.cwe_ids:
        session.add(CapecCweMapping(capec_id=pattern.capec_id, cwe_id=cwe_id))
    for technique_id in pattern.technique_ids:
        session.add(CapecAttackMapping(capec_id=pattern.capec_id, technique_id=technique_id))
    return Change.UPDATED if exists else Change.INSERTED


def upsert_advisory(session: Session, advisory: NormalizedAdvisory) -> Change:
    exists = session.get(Advisory, advisory.id) is not None
    values = {
        "id": advisory.id,
        "summary": advisory.summary,
        "details": advisory.details,
        "aliases": advisory.aliases,
        "cve_ids": advisory.cve_ids,
        "severity": advisory.severity,
        "cvss_vectors": advisory.cvss_vectors,
        "cwe_ids": advisory.cwe_ids,
        "references": advisory.references,
        "published_at": advisory.published_at,
        "modified_at": advisory.modified_at,
        "source_url": f"https://osv.dev/vulnerability/{advisory.id}",
    }
    stmt = insert(Advisory).values(**values)
    stmt = stmt.on_conflict_do_update(
        index_elements=[Advisory.id],
        set_={
            **{k: getattr(stmt.excluded, k) for k in values if k != "id"},
            "updated_at": func.now(),
        },
    )
    session.execute(stmt)
    session.execute(delete(AdvisoryPackage).where(AdvisoryPackage.advisory_id == advisory.id))
    for pkg in advisory.packages:
        session.add(
            AdvisoryPackage(
                advisory_id=advisory.id,
                ecosystem=pkg.ecosystem,
                name=pkg.name,
                normalized_name=pkg.normalized_name,
                purl=pkg.purl,
                ranges=pkg.ranges,
                versions=pkg.versions,
            )
        )
    return Change.UPDATED if exists else Change.INSERTED


def delete_advisory(session: Session, advisory_id: str) -> bool:
    result = session.execute(delete(Advisory).where(Advisory.id == advisory_id))
    return bool(result.rowcount)  # type: ignore[attr-defined]
