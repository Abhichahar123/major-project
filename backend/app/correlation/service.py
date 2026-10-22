"""Correlation queries. Each returned link carries its rule id and the evidence path."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.correlation.rules import RULES, rule_dicts
from app.db.models import (
    Advisory,
    AffectedProduct,
    AttackTechnique,
    CapecAttackMapping,
    CapecCweMapping,
    CapecPattern,
    CweEntry,
    KevEntry,
    Vulnerability,
    VulnerabilityCwe,
)

EXCLUDED_CAPEC_STATUS = {"Deprecated", "Obsolete", "Revoked"}
# Pillar/class-level CWEs that describe broad categories (MITRE marks several as
# discouraged for mapping). Chains that only pass through them are weak evidence.
BROAD_CWES = frozenset(
    {
        "CWE-20",
        "CWE-74",
        "CWE-200",
        "CWE-284",
        "CWE-664",
        "CWE-682",
        "CWE-691",
        "CWE-693",
        "CWE-697",
        "CWE-703",
        "CWE-707",
        "CWE-710",
        "CWE-400",
        "CWE-668",
        "CWE-669",
    }
)
RELATED_LIMIT = 10


def _technique_rows(session: Session, technique_ids: set[str]) -> dict[str, AttackTechnique]:
    if not technique_ids:
        return {}
    return {
        t.technique_id: t
        for t in session.scalars(
            select(AttackTechnique).where(AttackTechnique.technique_id.in_(technique_ids))
        )
    }


def _cwe_names(session: Session, cwe_ids: set[str]) -> dict[str, str | None]:
    if not cwe_ids:
        return {}
    return dict(
        session.execute(
            select(CweEntry.cwe_id, CweEntry.name).where(CweEntry.cwe_id.in_(cwe_ids))
        ).all()
    )


def chain_from_cwes(session: Session, cwe_ids: set[str]) -> dict[str, Any]:
    """CAPEC patterns and ATT&CK techniques reachable from the CWEs, with paths."""
    notes: list[str] = []
    if not cwe_ids:
        return {"patterns": [], "techniques": [], "notes": notes}
    rows = session.execute(
        select(CapecCweMapping.cwe_id, CapecPattern)
        .join(CapecPattern, CapecPattern.capec_id == CapecCweMapping.capec_id)
        .where(CapecCweMapping.cwe_id.in_(cwe_ids))
        .order_by(CapecPattern.capec_id)
    ).all()
    patterns: dict[str, dict[str, Any]] = {}
    excluded = set()
    for cwe_id, pattern in rows:
        if pattern.status in EXCLUDED_CAPEC_STATUS:
            excluded.add(pattern.capec_id)
            continue
        entry = patterns.setdefault(
            pattern.capec_id,
            {
                "capec_id": pattern.capec_id,
                "name": pattern.name,
                "status": pattern.status,
                "url": pattern.url,
                "via_cwes": [],
                "rule": "cwe_capec_mapping",
                "relationship": RULES["cwe_capec_mapping"].kind,
            },
        )
        entry["via_cwes"].append(cwe_id)
    if excluded:
        notes.append(f"{len(excluded)} deprecated/obsolete CAPEC pattern(s) were not used.")

    mappings = (
        session.execute(
            select(CapecAttackMapping.capec_id, CapecAttackMapping.technique_id).where(
                CapecAttackMapping.capec_id.in_(list(patterns))
            )
        ).all()
        if patterns
        else []
    )
    techniques_found = _technique_rows(session, {t for _, t in mappings})
    techniques: dict[str, dict[str, Any]] = {}
    skipped_revoked: set[str] = set()
    for capec_id, technique_id in mappings:
        tech = techniques_found.get(technique_id)
        if tech is not None and (tech.revoked or tech.deprecated):
            skipped_revoked.add(technique_id)
            continue
        entry = techniques.setdefault(
            technique_id,
            {
                "technique_id": technique_id,
                "name": tech.name if tech else None,
                "tactics": tech.tactics if tech else [],
                "url": tech.url if tech else None,
                "in_attack_dataset": tech is not None,
                "paths": [],
                "rule": "cve_cwe_capec_attack_chain",
                "relationship": "inferred",
            },
        )
        for cwe_id in patterns[capec_id]["via_cwes"]:
            entry["paths"].append(
                {"cwe_id": cwe_id, "capec_id": capec_id, "capec_name": patterns[capec_id]["name"]}
            )
    if skipped_revoked:
        notes.append(
            "Mappings to revoked or deprecated ATT&CK techniques were skipped: "
            + ", ".join(sorted(skipped_revoked))
            + "."
        )
    for entry in techniques.values():
        entry["path_count"] = len(entry["paths"])
        entry["supporting_cwes"] = sorted({p["cwe_id"] for p in entry["paths"]})
        specific = [c for c in entry["supporting_cwes"] if c not in BROAD_CWES]
        # Inferred links are never "high": the chain relates categories, not this CVE.
        entry["confidence"] = "medium" if specific and entry["path_count"] >= 2 else "low"
        entry["via_broad_cwe_only"] = not specific
    ranked = sorted(
        techniques.values(),
        key=lambda t: (
            t["confidence"] != "medium",
            t["via_broad_cwe_only"],
            -t["path_count"],
            t["technique_id"],
        ),
    )
    return {"patterns": list(patterns.values()), "techniques": ranked, "notes": notes}


def _related(session: Session, vuln: Vulnerability, cwe_ids: set[str]) -> list[dict[str, Any]]:
    related: dict[str, dict[str, Any]] = {}
    products = {
        (a.vendor.lower(), a.product.lower())
        for a in session.scalars(
            select(AffectedProduct).where(AffectedProduct.vulnerability_id == vuln.id)
        )
        if a.vendor and a.product
    }
    if products:
        rows = session.execute(
            select(
                Vulnerability.cve_id,
                func.lower(AffectedProduct.vendor),
                func.lower(AffectedProduct.product),
            )
            .join(AffectedProduct, AffectedProduct.vulnerability_id == Vulnerability.id)
            .where(
                Vulnerability.id != vuln.id,
                func.lower(AffectedProduct.vendor).in_({v for v, _ in products}),
                func.lower(AffectedProduct.product).in_({p for _, p in products}),
            )
        ).all()
        for cve_id, vendor, product in rows:
            if (vendor, product) not in products:
                continue
            item = related.setdefault(cve_id, {"cve_id": cve_id, "reasons": []})
            reason = {"rule": "shared_product", "shared": f"{vendor} {product}"}
            if reason not in item["reasons"]:
                item["reasons"].append(reason)
    if cwe_ids:
        rows = session.execute(
            select(Vulnerability.cve_id, VulnerabilityCwe.cwe_id)
            .join(VulnerabilityCwe, VulnerabilityCwe.vulnerability_id == Vulnerability.id)
            .where(Vulnerability.id != vuln.id, VulnerabilityCwe.cwe_id.in_(cwe_ids))
        ).all()
        for cve_id, cwe_id in rows:
            item = related.setdefault(cve_id, {"cve_id": cve_id, "reasons": []})
            reason = {"rule": "shared_weakness", "shared": cwe_id}
            if reason not in item["reasons"]:
                item["reasons"].append(reason)
    if not related:
        return []
    info = {
        v.cve_id: v
        for v in session.scalars(
            select(Vulnerability).where(Vulnerability.cve_id.in_(list(related)))
        )
    }
    kev_ids = set(
        session.scalars(select(KevEntry.cve_id).where(KevEntry.cve_id.in_(list(related))))
    )
    for cve_id, item in related.items():
        v = info[cve_id]
        item.update(
            {
                "title": v.title,
                "severity": v.severity,
                "cvss_base_score": v.cvss_base_score,
                "in_kev": cve_id in kev_ids,
                "relationship": "inferred",
            }
        )
    # Same product first, then more shared reasons, KEV entries, higher CVSS.
    return sorted(
        related.values(),
        key=lambda r: (
            not any(x["rule"] == "shared_product" for x in r["reasons"]),
            -len(r["reasons"]),
            not r["in_kev"],
            -(r["cvss_base_score"] or 0),
            r["cve_id"],
        ),
    )[:RELATED_LIMIT]


def correlate_vulnerability(session: Session, cve_id: str) -> dict[str, Any] | None:
    vuln = session.scalar(select(Vulnerability).where(Vulnerability.cve_id == cve_id))
    kev = session.get(KevEntry, cve_id)
    if vuln is None and kev is None:
        return None
    notes: list[str] = []

    stated: dict[str, set[str]] = defaultdict(set)
    if vuln is not None:
        for cwe_id, provider in session.execute(
            select(VulnerabilityCwe.cwe_id, VulnerabilityCwe.provider).where(
                VulnerabilityCwe.vulnerability_id == vuln.id
            )
        ):
            stated[cwe_id].add(provider)
    if kev is not None:
        for cwe_id in kev.cwes:
            stated[cwe_id].add("CISA KEV")
    names = _cwe_names(session, set(stated))
    weaknesses = [
        {
            "cwe_id": c,
            "name": names.get(c),
            "stated_by": sorted(p),
            "rule": "cve_cwe_assignment",
            "relationship": "authoritative",
        }
        for c, p in sorted(stated.items())
    ]
    if not weaknesses:
        notes.append("No CWE is assigned to this CVE, so no attack-pattern chain can be built.")

    chain = chain_from_cwes(session, set(stated))
    notes.extend(chain["notes"])
    if weaknesses and not chain["techniques"]:
        notes.append(
            "No ATT&CK technique is reachable: the CAPEC patterns for these CWEs "
            "carry no ATT&CK mapping (or none were found)."
        )

    advisories = [
        {
            "id": a.id,
            "summary": a.summary,
            "severity": a.severity,
            "url": a.source_url,
            "rule": "osv_alias",
            "relationship": "authoritative",
        }
        for a in session.scalars(
            select(Advisory).where(Advisory.cve_ids.contains([cve_id])).order_by(Advisory.id)
        )
    ]
    related = _related(session, vuln, set(stated)) if vuln is not None else []
    if vuln is None:
        notes.append("The CVE record is not ingested; only KEV data was used.")
    used_rules = [
        "cve_cwe_assignment",
        "cwe_capec_mapping",
        "capec_attack_mapping",
        "cve_cwe_capec_attack_chain",
        "shared_product",
        "shared_weakness",
        "kev_listing",
        "osv_alias",
    ]
    return {
        "cve_id": cve_id,
        "record_available": vuln is not None,
        "kev": {
            "listed": kev is not None,
            "date_added": kev.date_added if kev else None,
            "known_ransomware_use": kev.known_ransomware_use if kev else None,
            "rule": "kev_listing",
            "relationship": "authoritative",
        },
        "weaknesses": weaknesses,
        "attack_patterns": chain["patterns"],
        "techniques": chain["techniques"],
        "advisories": advisories,
        "related_vulnerabilities": related,
        "notes": notes,
        "rules": rule_dicts(used_rules),
    }


def technique_vulnerabilities(
    session: Session, technique_id: str, limit: int = 50
) -> dict[str, Any] | None:
    """CVEs whose weaknesses reach this technique through CAPEC (inferred), with paths."""
    tech = session.scalar(
        select(AttackTechnique).where(AttackTechnique.technique_id == technique_id)
    )
    if tech is None:
        return None
    capec_rows = session.execute(
        select(CapecAttackMapping.capec_id, CapecPattern.name, CapecPattern.status)
        .join(CapecPattern, CapecPattern.capec_id == CapecAttackMapping.capec_id)
        .where(CapecAttackMapping.technique_id == technique_id)
    ).all()
    patterns = {c: n for c, n, status in capec_rows if status not in EXCLUDED_CAPEC_STATUS}
    cwe_rows = (
        session.execute(
            select(CapecCweMapping.capec_id, CapecCweMapping.cwe_id).where(
                CapecCweMapping.capec_id.in_(list(patterns))
            )
        ).all()
        if patterns
        else []
    )
    capecs_by_cwe: dict[str, list[str]] = defaultdict(list)
    for capec_id, cwe_id in cwe_rows:
        capecs_by_cwe[cwe_id].append(capec_id)
    vulns: dict[str, dict[str, Any]] = {}
    if capecs_by_cwe:
        rows = session.execute(
            select(
                Vulnerability.cve_id,
                Vulnerability.title,
                Vulnerability.severity,
                Vulnerability.cvss_base_score,
                VulnerabilityCwe.cwe_id,
            )
            .join(VulnerabilityCwe, VulnerabilityCwe.vulnerability_id == Vulnerability.id)
            .where(VulnerabilityCwe.cwe_id.in_(list(capecs_by_cwe)))
        ).all()
        for cve_id, title, severity, score, cwe_id in rows:
            item = vulns.setdefault(
                cve_id,
                {
                    "cve_id": cve_id,
                    "title": title,
                    "severity": severity,
                    "cvss_base_score": score,
                    "paths": [],
                },
            )
            for capec_id in capecs_by_cwe[cwe_id]:
                path = {"cwe_id": cwe_id, "capec_id": capec_id, "capec_name": patterns[capec_id]}
                if path not in item["paths"]:
                    item["paths"].append(path)
    kev_ids = set(session.scalars(select(KevEntry.cve_id).where(KevEntry.cve_id.in_(list(vulns)))))
    items = []
    for item in vulns.values():
        item.update(
            {
                "in_kev": item["cve_id"] in kev_ids,
                "rule": "cve_cwe_capec_attack_chain",
                "relationship": "inferred",
                "path_count": len(item["paths"]),
            }
        )
        items.append(item)
    items.sort(
        key=lambda i: (-i["path_count"], not i["in_kev"], -(i["cvss_base_score"] or 0), i["cve_id"])
    )
    return {
        "technique_id": tech.technique_id,
        "name": tech.name,
        "capec_patterns": [{"capec_id": c, "name": n} for c, n in sorted(patterns.items())],
        "total": len(items),
        "vulnerabilities": items[:limit],
        "rules": rule_dicts(
            ["capec_attack_mapping", "cwe_capec_mapping", "cve_cwe_capec_attack_chain"]
        ),
    }


def cwe_overview(session: Session, cwe_id: str) -> dict[str, Any] | None:
    cwe = session.get(CweEntry, cwe_id)
    mapped = (
        session.scalar(
            select(func.count())
            .select_from(CapecCweMapping)
            .where(CapecCweMapping.cwe_id == cwe_id)
        )
        or 0
    )
    if cwe is None and not mapped:
        return None
    vuln_count = (
        session.scalar(
            select(func.count(func.distinct(VulnerabilityCwe.vulnerability_id))).where(
                VulnerabilityCwe.cwe_id == cwe_id
            )
        )
        or 0
    )
    kev_count = (
        session.scalar(
            select(func.count()).select_from(KevEntry).where(KevEntry.cwes.contains([cwe_id]))
        )
        or 0
    )
    chain = chain_from_cwes(session, {cwe_id})
    return {
        "cwe_id": cwe_id,
        "name": cwe.name if cwe else None,
        "url": f"https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[1]}.html",
        "vulnerability_count": vuln_count,
        "kev_count": kev_count,
        "attack_patterns": chain["patterns"],
        "techniques": chain["techniques"],
        "notes": chain["notes"],
        "rules": rule_dicts(["cwe_capec_mapping", "capec_attack_mapping"]),
    }
