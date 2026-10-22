"""Match parsed dependencies against stored vulnerability data.

Evidence sources, in order:

1. **OSV advisories** (ecosystem-exact package names and OSV ranges). A pinned version
   inside an affected range is a ``confirmed`` finding.
2. **CVE records** whose affected product or package name equals the dependency name.
   CVE records rarely say which package registry they mean, so these findings are
   ``uncertain`` even when the version falls in the stated range. CVEs already covered
   by an OSV advisory are not repeated.
3. Optionally the **OSV.dev API** (``OSV_ONLINE_LOOKUP=true``), for advisories not in the
   local export. Off by default because it sends package names to a third party.

Unpinned or unparsable versions never produce confirmed findings.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Literal

import httpx
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.db.models import Advisory, AdvisoryPackage, AffectedProduct, KevEntry, Vulnerability
from app.dependencies.parsers import Dependency, Manifest
from app.dependencies.versions import cve_entry_affected, osv_affected, parse_version

logger = logging.getLogger(__name__)

Confidence = Literal["confirmed", "uncertain"]
# Unpinned dependencies can match many historical advisories; list the most severe only.
MAX_UNPINNED_FINDINGS = 10


@dataclass
class Finding:
    package: str
    ecosystem: str
    version: str | None
    specifier: str | None
    location: str
    confidence: Confidence
    reason: str
    advisory_id: str | None
    cve_ids: list[str]
    severity: str | None
    summary: str | None
    fixed_versions: list[str]
    in_kev: bool
    source: str
    references: list[str] = field(default_factory=list)


@dataclass
class Report:
    format: str
    ecosystem: str
    dependency_count: int
    checked_count: int
    unpinned_count: int
    vulnerable_packages: int
    findings: list[Finding]
    not_checked: list[dict[str, str]]
    warnings: list[str]
    summary: dict[str, Any]
    sources: list[str]


def _fixed(ranges: list[dict[str, Any]]) -> list[str]:
    return sorted({e["fixed"] for r in ranges for e in r.get("events", []) if "fixed" in e})


_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4, None: 5}


def _osv_findings(
    session: Session, deps: list[Dependency]
) -> tuple[list[Finding], set[tuple[str, str]], list[str]]:
    names = {(d.ecosystem, d.normalized_name) for d in deps}
    if not names:
        return [], set(), []
    rows = session.execute(
        select(AdvisoryPackage, Advisory)
        .join(Advisory, Advisory.id == AdvisoryPackage.advisory_id)
        .where(
            or_(
                *[
                    (AdvisoryPackage.ecosystem == e) & (AdvisoryPackage.normalized_name == n)
                    for e, n in names
                ]
            )
        )
    ).all()
    by_name: dict[tuple[str, str], list[tuple[AdvisoryPackage, Advisory]]] = {}
    for pkg, adv in rows:
        by_name.setdefault((pkg.ecosystem, pkg.normalized_name), []).append((pkg, adv))

    findings: list[Finding] = []
    covered: set[tuple[str, str]] = set()
    warnings: list[str] = []
    for dep in deps:
        # One advisory may list the package several times (one per range): merge them.
        merged: dict[str, tuple[Advisory, list[dict[str, Any]], list[str]]] = {}
        for pkg, adv in by_name.get((dep.ecosystem, dep.normalized_name), []):
            _, ranges, versions = merged.setdefault(adv.id, (adv, [], []))
            ranges.extend(pkg.ranges)
            versions.extend(pkg.versions)
        # OSV is authoritative for this exact package: its CVEs are not re-checked against
        # CVE records, whatever the verdict.
        covered |= {(dep.normalized_name, c) for adv, _, _ in merged.values() for c in adv.cve_ids}

        reported: list[Finding] = []
        for adv, ranges, versions in _prefer_primary(list(merged.values())):
            if dep.pinned and dep.version:
                verdict = osv_affected(dep.ecosystem, dep.version, ranges, versions)
                if verdict is False:
                    continue
                confidence: Confidence = "confirmed" if verdict else "uncertain"
                reason = (
                    f"{dep.version} is inside an affected range of {adv.id}"
                    if verdict
                    else f"could not compare version {dep.version} with {adv.id} ranges"
                )
            else:
                if _specifier_excludes(dep, versions):
                    continue
                confidence = "uncertain"
                reason = (
                    f"version not pinned ({dep.specifier or 'any'}); {adv.id} affects some "
                    "versions of this package"
                )
            aliases = sorted(a for a in adv.aliases if not a.startswith("CVE-") and a != adv.id)
            reported.append(
                Finding(
                    package=dep.name,
                    ecosystem=dep.ecosystem,
                    version=dep.version,
                    specifier=dep.specifier,
                    location=dep.location,
                    confidence=confidence,
                    reason=reason
                    + (f" (also published as {', '.join(aliases)})" if aliases else ""),
                    advisory_id=adv.id,
                    cve_ids=list(adv.cve_ids),
                    severity=adv.severity,
                    summary=adv.summary,
                    fixed_versions=_fixed(ranges),
                    in_kev=False,
                    source="OSV advisory (local export)",
                    references=[adv.source_url] + [r["url"] for r in adv.references[:3]],
                )
            )
        if not dep.pinned and len(reported) > MAX_UNPINNED_FINDINGS:
            reported.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 5))
            warnings.append(
                f"{dep.name}: {len(reported)} advisories may apply to the declared range "
                f"{dep.specifier or '(any version)'}; showing the {MAX_UNPINNED_FINDINGS} most "
                "severe. Pin the version for an exact result."
            )
            reported = reported[:MAX_UNPINNED_FINDINGS]
        findings += reported
    return findings, covered, warnings


def _prefer_primary(
    items: list[tuple[Advisory, list[dict[str, Any]], list[str]]],
) -> list[tuple[Advisory, list[dict[str, Any]], list[str]]]:
    """Drop advisories that alias one already kept (e.g. PYSEC-x duplicating GHSA-y).

    GitHub-reviewed advisories (GHSA, which carry a severity) are kept in preference.
    """
    ordered = sorted(items, key=lambda i: (not i[0].id.startswith("GHSA-"), i[0].id))
    kept: list[tuple[Advisory, list[dict[str, Any]], list[str]]] = []
    seen: set[str] = set()
    for item in ordered:
        adv = item[0]
        identities = {adv.id, *adv.aliases}
        if identities & seen:
            continue
        seen |= identities
        kept.append(item)
    return kept


def _specifier_excludes(dep: Dependency, affected_versions: list[str]) -> bool:
    """True when OSV enumerates affected versions and none satisfies the PyPI specifier."""
    if dep.ecosystem != "PyPI" or not dep.specifier or not affected_versions:
        return False
    try:
        spec = SpecifierSet(dep.specifier)
    except InvalidSpecifier:
        return False
    return not any(spec.contains(v, prereleases=True) for v in affected_versions)


def _cve_findings(
    session: Session, deps: list[Dependency], covered: set[tuple[str, str]]
) -> list[Finding]:
    names = {d.normalized_name for d in deps}
    if not names:
        return []
    rows = session.execute(
        select(AffectedProduct, Vulnerability)
        .join(Vulnerability, Vulnerability.id == AffectedProduct.vulnerability_id)
        .where(
            Vulnerability.state == "PUBLISHED",
            or_(
                func.lower(AffectedProduct.package_name).in_(names),
                func.lower(AffectedProduct.product).in_(names),
            ),
        )
    ).all()
    # CVEs that OSV describes in any ecosystem have a precisely identified package; a bare
    # name match in another ecosystem would be a guess, so they are left to OSV.
    candidate_cves = list({vuln.cve_id for _, vuln in rows})
    osv_known = (
        {
            cve
            for ids in session.scalars(
                select(Advisory.cve_ids).where(Advisory.cve_ids.overlap(candidate_cves))
            )
            for cve in ids
        }
        if candidate_cves
        else set()
    )
    findings: list[Finding] = []
    for dep in deps:
        seen: set[str] = set()
        for product, vuln in rows:
            if vuln.cve_id in osv_known:
                continue
            name_match = dep.normalized_name in {
                (product.package_name or "").lower(),
                (product.product or "").lower(),
            }
            if not name_match or vuln.cve_id in seen:
                continue
            if (dep.normalized_name, vuln.cve_id) in covered:
                continue  # already reported through an OSV advisory
            if product.ecosystem and product.ecosystem != dep.ecosystem:
                continue
            verdicts = (
                [cve_entry_affected(dep.ecosystem, dep.version, e) for e in product.versions]
                if dep.pinned and dep.version
                else []
            )
            if verdicts and all(v is False for v in verdicts):
                continue
            seen.add(vuln.cve_id)
            in_range = any(v is True for v in verdicts)
            reason = (
                "product name matches and the version is inside the stated range"
                if in_range
                else "product name matches; affected versions could not be "
                "compared with this version"
            )
            findings.append(
                Finding(
                    package=dep.name,
                    ecosystem=dep.ecosystem,
                    version=dep.version,
                    specifier=dep.specifier,
                    location=dep.location,
                    confidence="uncertain",
                    reason=f"{reason} ({product.provider}: {product.vendor or '?'} "
                    f"{product.product or product.package_name})",
                    advisory_id=None,
                    cve_ids=[vuln.cve_id],
                    severity=vuln.severity,
                    summary=vuln.title or (vuln.description or "")[:200],
                    fixed_versions=[e["lessThan"] for e in product.versions if e.get("lessThan")][
                        :5
                    ],
                    in_kev=False,
                    source=f"CVE record ({product.ingest_source})",
                    references=[f"https://www.cve.org/CVERecord?id={vuln.cve_id}"],
                )
            )
    return findings


def _online_findings(
    client: httpx.Client, deps: list[Dependency], known_ids: set[str]
) -> tuple[list[Finding], list[str]]:
    pinned = [d for d in deps if d.pinned and d.version][:1000]
    if not pinned:
        return [], []
    try:
        response = client.post(
            "/querybatch",
            json={
                "queries": [
                    {"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version}
                    for d in pinned
                ]
            },
        )
        response.raise_for_status()
        results = response.json().get("results", [])
    except (httpx.HTTPError, ValueError) as exc:
        return [], [f"OSV.dev lookup failed ({type(exc).__name__}); local data only."]
    findings = []
    for dep, result in zip(pinned, results, strict=False):
        for vuln in (result or {}).get("vulns", []) or []:
            vid = vuln.get("id")
            if not isinstance(vid, str) or vid in known_ids or vid.startswith("MAL-"):
                continue
            findings.append(
                Finding(
                    package=dep.name,
                    ecosystem=dep.ecosystem,
                    version=dep.version,
                    specifier=dep.specifier,
                    location=dep.location,
                    confidence="confirmed",
                    reason=f"OSV.dev reports {vid} for {dep.name} {dep.version}",
                    advisory_id=vid,
                    cve_ids=[],
                    severity=None,
                    summary=None,
                    fixed_versions=[],
                    in_kev=False,
                    source="OSV.dev API",
                    references=[f"https://osv.dev/vulnerability/{vid}"],
                )
            )
    return findings, []


def analyze(session: Session, manifest: Manifest, osv_client: httpx.Client | None = None) -> Report:
    deps = manifest.dependencies
    findings, covered, osv_warnings = _osv_findings(session, deps)
    findings += _cve_findings(session, deps, covered)
    warnings = list(manifest.warnings) + osv_warnings
    sources = ["OSV advisories (local export)", "CVE records (product-name match)"]
    if osv_client is not None:
        extra, errors = _online_findings(
            osv_client, deps, {f.advisory_id for f in findings if f.advisory_id}
        )
        findings += extra
        warnings += errors
        sources.append("OSV.dev API")

    cve_ids = {c for f in findings for c in f.cve_ids}
    kev = (
        set(session.scalars(select(KevEntry.cve_id).where(KevEntry.cve_id.in_(cve_ids))))
        if cve_ids
        else set()
    )
    for finding in findings:
        finding.in_kev = any(c in kev for c in finding.cve_ids)
    findings.sort(
        key=lambda f: (
            f.confidence != "confirmed",
            not f.in_kev,
            _SEVERITY_ORDER.get(f.severity, 5),
            f.package.lower(),
            f.advisory_id or "",
        )
    )
    invalid_versions = [
        d for d in deps if d.pinned and d.version and parse_version(d.ecosystem, d.version) is None
    ]
    if invalid_versions:
        warnings.append(
            f"{len(invalid_versions)} version(s) could not be parsed for "
            f"{manifest.ecosystem}; their matches are uncertain."
        )
    confirmed_packages = {(f.package, f.version) for f in findings if f.confidence == "confirmed"}
    by_severity: dict[str, int] = {}
    for f in findings:
        if f.confidence == "confirmed":
            key = f.severity or "UNSCORED"
            by_severity[key] = by_severity.get(key, 0) + 1
    return Report(
        format=manifest.format,
        ecosystem=manifest.ecosystem,
        dependency_count=len(deps),
        checked_count=sum(1 for d in deps if d.pinned),
        unpinned_count=sum(1 for d in deps if not d.pinned),
        vulnerable_packages=len(confirmed_packages),
        findings=findings,
        not_checked=manifest.not_checked,
        warnings=warnings,
        summary={
            "confirmed_findings": sum(1 for f in findings if f.confidence == "confirmed"),
            "uncertain_findings": sum(1 for f in findings if f.confidence == "uncertain"),
            "confirmed_by_severity": by_severity,
            "in_kev": sum(1 for f in findings if f.in_kev),
        },
        sources=sources,
    )
