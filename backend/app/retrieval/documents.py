"""Turn stored records into retrievable text chunks.

One document per entity:

* ``vulnerability``: a CVE record with its scores, CWEs, affected products, CISA KEV
  status and OSV fix information (all from the database, with the source named);
* ``kev``: a CISA KEV entry whose CVE record has not been ingested;
* ``attack_technique``: a MITRE ATT&CK technique.

Each chunk starts with a header line naming the entity, so identifiers survive chunking
and every chunk can be cited on its own. ``sync_documents`` is idempotent: chunks are
rewritten only when their text changes, and an unchanged chunk keeps its embedding.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import delete, select, tuple_
from sqlalchemy.orm import Session

from app.db.models import (
    AffectedProduct,
    AttackTechnique,
    CweEntry,
    DocumentChunk,
    KevEntry,
    Vulnerability,
    VulnerabilityCwe,
)
from app.services.catalog import advisories_for_cves

MAX_CHUNK_CHARS = 1200
OVERLAP_CHARS = 150
MAX_AFFECTED_LINES = 15


@dataclass
class Document:
    entity_type: str
    entity_id: str
    cve_id: str | None
    title: str
    body: str
    source_name: str
    source_url: str | None
    metadata: dict[str, Any] = field(default_factory=dict)


def _split(text: str, limit: int = MAX_CHUNK_CHARS, overlap: int = OVERLAP_CHARS) -> list[str]:
    """Split on paragraph, then sentence, then word boundaries with a small overlap."""
    text = text.strip()
    if len(text) <= limit:
        return [text] if text else []
    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = min(len(text), start + limit)
        if end < len(text):
            window = text[start:end]
            cut = max(window.rfind("\n\n"), window.rfind(". "), window.rfind("\n"))
            if cut < limit // 2:
                cut = window.rfind(" ")
            if cut > 0:
                end = start + cut + 1
        chunks.append(text[start:end].strip())
        if end >= len(text):
            break
        start = max(end - overlap, start + 1)
        # Do not begin a chunk mid-word.
        while start < len(text) and not text[start - 1].isspace():
            start += 1
    return [c for c in chunks if c]


def chunk_document(doc: Document) -> list[tuple[str, str]]:
    """Return (content, sha256) pairs, each content prefixed with the document header."""
    header = doc.title
    out = []
    for part in _split(doc.body, MAX_CHUNK_CHARS - len(header) - 1):
        content = f"{header}\n{part}"
        out.append((content, hashlib.sha256(content.encode()).hexdigest()))
    return out


def _version_text(versions: list[dict[str, Any]]) -> str:
    parts = []
    for v in versions[:6]:
        if v.get("status") not in (None, "affected"):
            continue
        piece = v.get("version") or ""
        if v.get("lessThan"):
            piece = f"{piece} to before {v['lessThan']}".strip()
        elif v.get("lessThanOrEqual"):
            piece = f"{piece} through {v['lessThanOrEqual']}".strip()
        if piece:
            parts.append(piece)
    return "; ".join(parts)


def vulnerability_documents(session: Session) -> Iterator[Document]:
    vulns = session.scalars(select(Vulnerability).order_by(Vulnerability.id)).all()
    kev = {k.cve_id: k for k in session.scalars(select(KevEntry))}
    cwe_rows = session.execute(
        select(VulnerabilityCwe.vulnerability_id, VulnerabilityCwe.cwe_id, CweEntry.name).join(
            CweEntry, CweEntry.cwe_id == VulnerabilityCwe.cwe_id
        )
    ).all()
    cwes: dict[int, dict[str, str | None]] = {}
    for vid, cwe_id, name in cwe_rows:
        cwes.setdefault(vid, {})[cwe_id] = name
    affected: dict[int, list[AffectedProduct]] = {}
    for row in session.scalars(select(AffectedProduct).order_by(AffectedProduct.id)):
        affected.setdefault(row.vulnerability_id, []).append(row)
    advisories = advisories_for_cves(session, [v.cve_id for v in vulns])

    for v in vulns:
        lines = []
        if v.state == "REJECTED":
            lines.append("Status: REJECTED by the CVE Program.")
        if v.description:
            lines.append(v.description)
        if v.severity:
            lines.append(
                f"Severity: {v.severity} (CVSS {v.cvss_version} base score {v.cvss_base_score}, "
                f"scored by {v.cvss_provider})."
            )
        else:
            lines.append("Severity: no CVSS score in the stored records.")
        for cwe_id, name in sorted(cwes.get(v.id, {}).items()):
            lines.append(f"Weakness: {cwe_id}" + (f" {name}" if name else "") + ".")
        seen_products: set[tuple[str | None, str | None]] = set()
        for a in affected.get(v.id, []):
            key = (a.vendor, a.product or a.package_name)
            if key in seen_products or len(seen_products) >= MAX_AFFECTED_LINES:
                continue
            seen_products.add(key)
            versions = _version_text(a.versions)
            name = " ".join(x for x in key if x)
            lines.append(
                f"Affected product: {name}"
                + (f" (versions: {versions})" if versions else "")
                + f" according to {a.provider}."
            )
        entry = kev.get(v.cve_id)
        if entry:
            lines.append(
                f"CISA KEV: listed as known exploited since {entry.date_added.isoformat()}; "
                f"known ransomware use: {entry.known_ransomware_use}. "
                f"Required action: {entry.required_action}"
            )
        else:
            lines.append("CISA KEV: not listed in the stored KEV catalog.")
        for adv in advisories.get(v.cve_id, [])[:5]:
            for pkg in adv["packages"][:5]:
                fixed = ", ".join(pkg["fixed_versions"]) or "no fixed version listed"
                lines.append(
                    f"Advisory {adv['id']} ({pkg['ecosystem']} package {pkg['name']}): "
                    f"fixed in {fixed}."
                )
        title = f"{v.cve_id}: {v.title}" if v.title else v.cve_id
        yield Document(
            entity_type="vulnerability",
            entity_id=v.cve_id,
            cve_id=v.cve_id,
            title=title,
            body="\n".join(lines),
            source_name="CVE Program record" + (" + CISA KEV" if entry else ""),
            source_url=f"https://www.cve.org/CVERecord?id={v.cve_id}",
            metadata={
                "severity": v.severity,
                "cvss_base_score": v.cvss_base_score,
                "in_kev": entry is not None,
                "published": v.published_at.date().isoformat() if v.published_at else None,
                "cwes": sorted(cwes.get(v.id, {})),
                "state": v.state,
            },
        )


def kev_only_documents(session: Session) -> Iterator[Document]:
    stmt = select(KevEntry).where(
        ~select(Vulnerability.id).where(Vulnerability.cve_id == KevEntry.cve_id).exists()
    )
    for entry in session.scalars(stmt.order_by(KevEntry.cve_id)):
        body = (
            f"{entry.short_description}\n"
            f"Vendor: {entry.vendor_project}. Product: {entry.product}.\n"
            f"CISA KEV: listed as known exploited since {entry.date_added.isoformat()}; known "
            f"ransomware use: {entry.known_ransomware_use}. Required action: "
            f"{entry.required_action}"
            + (f"\nWeaknesses: {', '.join(entry.cwes)}." if entry.cwes else "")
        )
        yield Document(
            entity_type="kev",
            entity_id=entry.cve_id,
            cve_id=entry.cve_id,
            title=f"{entry.cve_id}: {entry.vulnerability_name}",
            body=body,
            source_name="CISA KEV",
            source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            metadata={
                "severity": None,
                "in_kev": True,
                "cwes": entry.cwes,
                "published": None,
                "state": "KEV_ONLY",
            },
        )


def technique_documents(session: Session) -> Iterator[Document]:
    stmt = select(AttackTechnique).where(~AttackTechnique.revoked, ~AttackTechnique.deprecated)
    for t in session.scalars(stmt.order_by(AttackTechnique.technique_id)):
        body = (
            (t.description or "")
            + f"\nTactics: {', '.join(t.tactics) or 'none listed'}."
            + f"\nPlatforms: {', '.join(t.platforms) or 'none listed'}."
        )
        yield Document(
            entity_type="attack_technique",
            entity_id=t.technique_id,
            cve_id=None,
            title=f"{t.technique_id}: {t.name} (MITRE ATT&CK)",
            body=body,
            source_name="MITRE ATT&CK",
            source_url=t.url,
            metadata={"tactics": t.tactics, "in_kev": False, "severity": None},
        )


DOCUMENT_BUILDERS = {
    "vulnerability": vulnerability_documents,
    "kev": kev_only_documents,
    "attack_technique": technique_documents,
}


@dataclass
class SyncResult:
    documents: int = 0
    chunks_written: int = 0
    chunks_unchanged: int = 0
    chunks_removed: int = 0


def sync_documents(session: Session, entity_types: list[str]) -> SyncResult:
    """Rebuild chunks for the given entity types, touching only changed chunks."""
    result = SyncResult()
    for entity_type in entity_types:
        existing: dict[tuple[str, int], DocumentChunk] = {
            (c.entity_id, c.chunk_index): c
            for c in session.scalars(
                select(DocumentChunk).where(DocumentChunk.entity_type == entity_type)
            )
        }
        wanted: set[tuple[str, int]] = set()
        for doc in DOCUMENT_BUILDERS[entity_type](session):
            result.documents += 1
            for index, (content, digest) in enumerate(chunk_document(doc)):
                key = (doc.entity_id, index)
                wanted.add(key)
                current = existing.get(key)
                if current is not None and current.content_hash == digest:
                    result.chunks_unchanged += 1
                    continue
                if current is not None:
                    session.delete(current)  # its embeddings are removed by cascade
                    session.flush()
                session.add(
                    DocumentChunk(
                        entity_type=entity_type,
                        entity_id=doc.entity_id,
                        cve_id=doc.cve_id,
                        chunk_index=index,
                        title=doc.title,
                        content=content,
                        content_hash=digest,
                        source_name=doc.source_name,
                        source_url=doc.source_url,
                        metadata_=doc.metadata,
                    )
                )
                result.chunks_written += 1
        stale = [key for key in existing if key not in wanted]
        if stale:
            session.execute(
                delete(DocumentChunk).where(
                    DocumentChunk.entity_type == entity_type,
                    tuple_(DocumentChunk.entity_id, DocumentChunk.chunk_index).in_(stale),
                )
            )
            result.chunks_removed += len(stale)
        session.flush()
    return result
