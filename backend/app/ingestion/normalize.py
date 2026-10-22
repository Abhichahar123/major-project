"""Validation and normalization of upstream records.

Pure functions: raw JSON in, typed records out. A record that cannot be interpreted
raises ``RecordError`` with a short reason; callers log it and continue with the batch.

Display severity rule (``select_display_cvss``):

1. Providers are ranked CNA, then NVD primary, then CISA-ADP, then any other.
2. Within a provider, CVSS v3.1 > v3.0 > v4.0 > v2.0. v3.x is preferred because it is the
   most widely populated version, which keeps severity filters comparable across records.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Any
from urllib.parse import urlsplit

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
CWE_ID_RE = re.compile(r"^CWE-\d+$")
TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
CAPEC_ID_RE = re.compile(r"^CAPEC-\d+$")
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE")

MAX_TEXT = 20_000
MAX_SHORT = 300
MAX_URL = 2000
MAX_VERSIONS_PER_PRODUCT = 200
MAX_PRODUCTS = 200
MAX_REFERENCES = 300

# collectionURL -> OSV-style ecosystem name, only for unambiguous package registries.
ECOSYSTEM_BY_HOST = {
    "pypi.org": "PyPI",
    "pypi.python.org": "PyPI",
    "registry.npmjs.org": "npm",
    "www.npmjs.com": "npm",
    "npmjs.com": "npm",
    "repo.maven.apache.org": "Maven",
    "repo1.maven.org": "Maven",
    "search.maven.org": "Maven",
    "rubygems.org": "RubyGems",
    "crates.io": "crates.io",
    "proxy.golang.org": "Go",
    "pkg.go.dev": "Go",
    "packagist.org": "Packagist",
    "www.nuget.org": "NuGet",
    "nuget.org": "NuGet",
}

_CVSS_KEYS = {"cvssV4_0": "4.0", "cvssV3_1": "3.1", "cvssV3_0": "3.0", "cvssV2_0": "2.0"}
_VERSION_RANK = {"3.1": 0, "3.0": 1, "4.0": 2, "2.0": 3}


class RecordError(ValueError):
    """A single upstream record is malformed or unsupported."""


# ------------------------------------------------------------------------- helpers


def content_hash(payload: Any) -> str:
    """Stable SHA-256 of a JSON-compatible payload (key order independent)."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def clean_text(value: Any, limit: int = MAX_TEXT) -> str | None:
    if not isinstance(value, str):
        return None
    # Drop NUL and other C0 control characters except tab/newline; PostgreSQL rejects NUL.
    text = "".join(ch for ch in value if ch in "\t\n" or ord(ch) >= 32).strip()
    return text[:limit] or None


# Values CNAs use to mean "not specified"; stored as missing rather than as a name.
_PLACEHOLDERS = frozenset({"n/a", "na", "none", "unspecified", "unknown", "-", "*", "0"})


def clean_identifier(value: Any, limit: int = MAX_SHORT) -> str | None:
    text = clean_text(value, limit)
    return None if text is None or text.lower() in _PLACEHOLDERS else text


def parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def parse_date(value: Any) -> date | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


def normalize_cve_id(value: Any) -> str:
    cve_id = value.strip().upper() if isinstance(value, str) else ""
    if not CVE_ID_RE.match(cve_id):
        raise RecordError(f"invalid CVE identifier: {str(value)[:40]!r}")
    return cve_id


def normalize_cwe_id(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    cwe = value.strip().upper()
    return cwe if CWE_ID_RE.match(cwe) else None


def safe_url(value: Any) -> str | None:
    """Accept only http(s) URLs of reasonable length; stored as data, never fetched."""
    if not isinstance(value, str):
        return None
    url = value.strip()
    if len(url) > MAX_URL:
        return None
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        return None
    return url


def severity_from_score(score: float) -> str:
    if score == 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def cve5_record_path(cve_id: str) -> str:
    """Path of a record in CVEProject/cvelistV5: cves/<year>/<n // 1000>xxx/<id>.json."""
    _, year, number = cve_id.split("-")
    return f"{year}/{int(number) // 1000}xxx/{cve_id}.json"


# ------------------------------------------------------------------ vulnerability


@dataclass
class CvssScore:
    provider: str
    version: str
    base_score: float
    base_severity: str | None
    vector: str | None
    provider_rank: int  # lower is preferred for display


@dataclass
class AffectedEntry:
    provider: str
    vendor: str | None
    product: str | None
    package_name: str | None = None
    collection_url: str | None = None
    ecosystem: str | None = None
    default_status: str | None = None
    cpes: list[str] = field(default_factory=list)
    versions: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class Reference:
    url: str
    name: str | None = None
    tags: list[str] = field(default_factory=list)


@dataclass
class NormalizedVulnerability:
    cve_id: str
    state: str
    title: str | None
    description: str | None
    assigner: str | None
    published_at: datetime | None
    source_updated_at: datetime | None
    cvss: list[CvssScore] = field(default_factory=list)
    cwes: list[tuple[str, str, str | None]] = field(default_factory=list)  # (cwe, provider, name)
    affected: list[AffectedEntry] = field(default_factory=list)
    references: list[Reference] = field(default_factory=list)


def select_display_cvss(scores: list[CvssScore]) -> CvssScore | None:
    if not scores:
        return None
    return min(scores, key=lambda s: (s.provider_rank, _VERSION_RANK.get(s.version, 9)))


def _cvss_from_cve5(metrics: Any, provider: str, rank: int) -> list[CvssScore]:
    scores: list[CvssScore] = []
    if not isinstance(metrics, list):
        return scores
    for metric in metrics:
        if not isinstance(metric, dict):
            continue
        for key, version in _CVSS_KEYS.items():
            data = metric.get(key)
            if not isinstance(data, dict):
                continue
            score = data.get("baseScore")
            if not isinstance(score, int | float) or not 0 <= score <= 10:
                continue
            severity = data.get("baseSeverity")
            severity = severity.upper() if isinstance(severity, str) else None
            if severity not in SEVERITIES:
                severity = severity_from_score(float(score))
            scores.append(
                CvssScore(
                    provider=provider,
                    version=version,
                    base_score=float(score),
                    base_severity=severity,
                    vector=clean_text(data.get("vectorString"), 200),
                    provider_rank=rank,
                )
            )
    return scores


def _cwe_name(description: Any, cwe_id: str) -> str | None:
    text = clean_text(description, MAX_SHORT)
    if not text:
        return None
    # "CWE-79: Improper Neutralization..." or "CWE-502 Deserialization of Untrusted Data"
    name = re.sub(rf"^{cwe_id}\s*[:\-]?\s*", "", text).strip()
    return name or None


def _cwes_from_cve5(problem_types: Any, provider: str) -> list[tuple[str, str, str | None]]:
    out: list[tuple[str, str, str | None]] = []
    if not isinstance(problem_types, list):
        return out
    for problem in problem_types:
        for desc in (problem or {}).get("descriptions", []) or []:
            if not isinstance(desc, dict):
                continue
            cwe = normalize_cwe_id(desc.get("cweId"))
            if cwe:
                out.append((cwe, provider, _cwe_name(desc.get("description"), cwe)))
    return out


def _version_entries(raw: Any) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    if not isinstance(raw, list):
        return entries
    for item in raw[:MAX_VERSIONS_PER_PRODUCT]:
        if not isinstance(item, dict):
            continue
        entry: dict[str, Any] = {}
        for key in ("version", "status", "lessThan", "lessThanOrEqual", "versionType"):
            value = clean_text(item.get(key), 200)
            if key in {"version", "lessThan", "lessThanOrEqual"} and value is not None:
                # "0" is a meaningful lower bound in ranges, so only drop textual placeholders.
                value = None if value.lower() in _PLACEHOLDERS - {"0", "*"} else value
            if value:
                entry[key] = value
        changes = [
            {"at": clean_text(c.get("at"), 200), "status": clean_text(c.get("status"), 32)}
            for c in item.get("changes", []) or []
            if isinstance(c, dict) and c.get("at")
        ]
        if changes:
            entry["changes"] = changes[:50]
        if entry.get("version") or entry.get("lessThan") or entry.get("lessThanOrEqual"):
            entries.append(entry)
    return entries


def ecosystem_for(collection_url: str | None) -> str | None:
    if not collection_url:
        return None
    return ECOSYSTEM_BY_HOST.get((urlsplit(collection_url).hostname or "").lower())


def _affected_from_cve5(affected: Any, provider: str) -> list[AffectedEntry]:
    entries: list[AffectedEntry] = []
    if not isinstance(affected, list):
        return entries
    for item in affected[:MAX_PRODUCTS]:
        if not isinstance(item, dict):
            continue
        collection_url = safe_url(item.get("collectionURL"))
        cpes = [c for c in item.get("cpes", []) or [] if isinstance(c, str) and len(c) < 500]
        entry = AffectedEntry(
            provider=provider,
            vendor=clean_identifier(item.get("vendor")),
            product=clean_identifier(item.get("product")),
            package_name=clean_identifier(item.get("packageName")),
            collection_url=collection_url,
            ecosystem=ecosystem_for(collection_url),
            default_status=clean_text(item.get("defaultStatus"), 16),
            cpes=cpes[:50],
            versions=_version_entries(item.get("versions")),
        )
        if entry.vendor or entry.product or entry.package_name:
            entries.append(entry)
    return entries


def _references(raw: Any) -> list[Reference]:
    refs: list[Reference] = []
    if not isinstance(raw, list):
        return refs
    for item in raw:
        if not isinstance(item, dict):
            continue
        url = safe_url(item.get("url"))
        if not url:
            continue
        tags = [t[:64] for t in item.get("tags", []) or [] if isinstance(t, str)][:20]
        refs.append(Reference(url=url, name=clean_text(item.get("name"), 500), tags=tags))
    return refs


def _dedupe_references(refs: list[Reference]) -> list[Reference]:
    seen: dict[str, Reference] = {}
    for ref in refs:
        if ref.url in seen:
            merged = seen[ref.url]
            merged.tags = sorted(set(merged.tags) | set(ref.tags))
        else:
            seen[ref.url] = ref
    return list(seen.values())[:MAX_REFERENCES]


def _english(descriptions: Any) -> str | None:
    if not isinstance(descriptions, list):
        return None
    english = [
        d.get("value")
        for d in descriptions
        if isinstance(d, dict) and str(d.get("lang", "")).lower().startswith("en")
    ]
    return clean_text(english[0]) if english else None


def parse_cve5(record: Any) -> NormalizedVulnerability:
    """Normalize a CVE JSON 5.x record (CNA container plus ADP containers)."""
    if not isinstance(record, dict) or record.get("dataType") != "CVE_RECORD":
        raise RecordError("not a CVE JSON 5 record")
    meta = record.get("cveMetadata") or {}
    cve_id = normalize_cve_id(meta.get("cveId"))
    state = str(meta.get("state", "")).upper()
    if state not in {"PUBLISHED", "REJECTED"}:
        raise RecordError(f"unsupported record state {state[:20]!r}")
    containers = record.get("containers") or {}
    cna = containers.get("cna") or {}
    if not isinstance(cna, dict):
        raise RecordError("missing CNA container")

    assigner = clean_text(meta.get("assignerShortName"), 100)
    cna_provider = clean_text((cna.get("providerMetadata") or {}).get("shortName"), 100)
    cna_provider = cna_provider or assigner or "CNA"

    if state == "REJECTED":
        description = _english(cna.get("rejectedReasons"))
    else:
        description = _english(cna.get("descriptions"))

    vuln = NormalizedVulnerability(
        cve_id=cve_id,
        state=state,
        title=clean_text(cna.get("title"), 1000),
        description=description,
        assigner=assigner,
        published_at=parse_datetime(meta.get("datePublished")),
        source_updated_at=parse_datetime(meta.get("dateUpdated")),
    )
    vuln.cvss.extend(_cvss_from_cve5(cna.get("metrics"), cna_provider, 0))
    vuln.cwes.extend(_cwes_from_cve5(cna.get("problemTypes"), cna_provider))
    vuln.affected.extend(_affected_from_cve5(cna.get("affected"), cna_provider))
    refs = _references(cna.get("references"))

    for adp in containers.get("adp", []) or []:
        if not isinstance(adp, dict):
            continue
        provider = clean_text((adp.get("providerMetadata") or {}).get("shortName"), 100) or "ADP"
        rank = 2 if provider == "CISA-ADP" else 3
        vuln.cvss.extend(_cvss_from_cve5(adp.get("metrics"), provider, rank))
        vuln.cwes.extend(_cwes_from_cve5(adp.get("problemTypes"), provider))
        vuln.affected.extend(_affected_from_cve5(adp.get("affected"), provider))
        refs.extend(_references(adp.get("references")))

    vuln.references = _dedupe_references(refs)
    vuln.cwes = list(dict.fromkeys(vuln.cwes))
    return vuln


# --------------------------------------------------------------------------- NVD


def _parse_cpe(criteria: str) -> tuple[str | None, str | None, str | None]:
    # cpe:2.3:part:vendor:product:version:update:...
    parts = criteria.split(":")
    if len(parts) < 6 or parts[0] != "cpe":
        return None, None, None

    def unescape(value: str) -> str | None:
        return None if value in {"*", "-", ""} else value.replace("\\", "")

    return unescape(parts[3]), unescape(parts[4]), unescape(parts[5])


def parse_nvd(item: Any) -> NormalizedVulnerability:
    """Normalize one element of the NVD CVE API 2.0 ``vulnerabilities`` array."""
    cve = (item or {}).get("cve") if isinstance(item, dict) else None
    if not isinstance(cve, dict):
        raise RecordError("missing 'cve' object")
    cve_id = normalize_cve_id(cve.get("id"))
    status = str(cve.get("vulnStatus", ""))
    vuln = NormalizedVulnerability(
        cve_id=cve_id,
        state="REJECTED" if status.lower() == "rejected" else "PUBLISHED",
        title=None,
        description=_english(cve.get("descriptions")),
        assigner=clean_text(cve.get("sourceIdentifier"), 100),
        published_at=parse_datetime(cve.get("published")),
        source_updated_at=parse_datetime(cve.get("lastModified")),
    )
    metrics = cve.get("metrics") or {}
    for key, version in (
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ):
        for metric in metrics.get(key, []) or []:
            data = (metric or {}).get("cvssData") or {}
            score = data.get("baseScore")
            if not isinstance(score, int | float) or not 0 <= score <= 10:
                continue
            severity = data.get("baseSeverity") or metric.get("baseSeverity")
            severity = severity.upper() if isinstance(severity, str) else None
            if severity not in SEVERITIES:
                severity = severity_from_score(float(score))
            provider = clean_text(metric.get("source"), 100) or "nvd"
            primary = metric.get("type") == "Primary"
            rank = 1 if primary and provider == "nvd@nist.gov" else 3
            vuln.cvss.append(
                CvssScore(
                    provider,
                    version,
                    float(score),
                    severity,
                    clean_text(data.get("vectorString"), 200),
                    rank,
                )
            )
    for weakness in cve.get("weaknesses", []) or []:
        provider = clean_text((weakness or {}).get("source"), 100) or "nvd"
        for desc in (weakness or {}).get("description", []) or []:
            cwe = normalize_cwe_id((desc or {}).get("value"))  # skips NVD-CWE-noinfo/Other
            if cwe:
                vuln.cwes.append((cwe, provider, None))
    vuln.cwes = list(dict.fromkeys(vuln.cwes))

    grouped: dict[tuple[str | None, str | None], AffectedEntry] = {}
    for config in cve.get("configurations", []) or []:
        for node in (config or {}).get("nodes", []) or []:
            for match in (node or {}).get("cpeMatch", []) or []:
                if not isinstance(match, dict) or not match.get("vulnerable"):
                    continue
                criteria = match.get("criteria")
                if not isinstance(criteria, str):
                    continue
                vendor, product, cpe_version = _parse_cpe(criteria)
                if not product:
                    continue
                entry = grouped.setdefault(
                    (vendor, product),
                    AffectedEntry(provider="nvd@nist.gov", vendor=vendor, product=product),
                )
                if criteria not in entry.cpes and len(entry.cpes) < 50:
                    entry.cpes.append(criteria)
                version_entry: dict[str, Any] = {"status": "affected", "versionType": "cpe"}
                if cpe_version:
                    version_entry["version"] = cpe_version
                for src, dst in (
                    ("versionStartIncluding", "version"),
                    ("versionStartExcluding", "versionStartExcluding"),
                    ("versionEndExcluding", "lessThan"),
                    ("versionEndIncluding", "lessThanOrEqual"),
                ):
                    value = clean_text(match.get(src), 200)
                    if value:
                        version_entry[dst] = value
                if len(version_entry) > 2 and len(entry.versions) < MAX_VERSIONS_PER_PRODUCT:
                    entry.versions.append(version_entry)
    vuln.affected = list(grouped.values())[:MAX_PRODUCTS]
    vuln.references = _dedupe_references(_references(cve.get("references")))
    return vuln


# --------------------------------------------------------------------------- KEV


@dataclass
class NormalizedKev:
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
    raw: dict[str, Any]


def parse_kev_catalog(catalog: Any) -> tuple[str | None, list[dict[str, Any]]]:
    if not isinstance(catalog, dict) or not isinstance(catalog.get("vulnerabilities"), list):
        raise RecordError("KEV catalog has no 'vulnerabilities' array")
    version = clean_text(catalog.get("catalogVersion"), 32)
    return version, catalog["vulnerabilities"]


def parse_kev_entry(item: Any) -> NormalizedKev:
    if not isinstance(item, dict):
        raise RecordError("KEV entry is not an object")
    cve_id = normalize_cve_id(item.get("cveID"))
    date_added = parse_date(item.get("dateAdded"))
    if date_added is None:
        raise RecordError(f"{cve_id}: missing or invalid dateAdded")
    required = {
        "vendor_project": clean_text(item.get("vendorProject"), MAX_SHORT),
        "product": clean_text(item.get("product"), MAX_SHORT),
        "vulnerability_name": clean_text(item.get("vulnerabilityName"), 1000),
        "short_description": clean_text(item.get("shortDescription")),
        "required_action": clean_text(item.get("requiredAction")),
    }
    missing = [k for k, v in required.items() if not v]
    if missing:
        raise RecordError(f"{cve_id}: missing {', '.join(missing)}")
    ransomware = clean_text(item.get("knownRansomwareCampaignUse"), 16) or "Unknown"
    cwes = [c for c in (normalize_cwe_id(x) for x in item.get("cwes", []) or []) if c]
    return NormalizedKev(
        cve_id=cve_id,
        notes=clean_text(item.get("notes")),
        date_added=date_added,
        due_date=parse_date(item.get("dueDate")),
        known_ransomware_use=ransomware,
        cwes=cwes,
        raw=item,
        **required,  # type: ignore[arg-type]
    )


# ------------------------------------------------------------------- ATT&CK / CAPEC


@dataclass
class NormalizedTechnique:
    stix_id: str
    technique_id: str
    name: str
    description: str | None
    tactics: list[str]
    platforms: list[str]
    is_subtechnique: bool
    parent_technique_id: str | None
    url: str | None
    deprecated: bool
    revoked: bool
    source_modified_at: datetime | None
    raw: dict[str, Any]


def stix_objects(bundle: Any) -> list[dict[str, Any]]:
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        raise RecordError("not a STIX bundle")
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise RecordError("STIX bundle has no objects")
    return [o for o in objects if isinstance(o, dict)]


def attack_version(objects: list[dict[str, Any]]) -> str | None:
    for obj in objects:
        if obj.get("type") == "x-mitre-collection":
            return clean_text(obj.get("x_mitre_version"), 16)
    return None


def parse_attack_technique(obj: dict[str, Any]) -> NormalizedTechnique:
    stix_id = obj.get("id")
    if not isinstance(stix_id, str) or not stix_id.startswith("attack-pattern--"):
        raise RecordError("not an ATT&CK attack-pattern")
    ref = next(
        (
            r
            for r in obj.get("external_references", []) or []
            if isinstance(r, dict) and r.get("source_name") == "mitre-attack"
        ),
        None,
    )
    technique_id = str((ref or {}).get("external_id", "")).upper()
    if not TECHNIQUE_ID_RE.match(technique_id):
        raise RecordError(f"{stix_id}: missing ATT&CK technique ID")
    name = clean_text(obj.get("name"), MAX_SHORT)
    if not name:
        raise RecordError(f"{technique_id}: missing name")
    tactics = [
        str(p.get("phase_name"))
        for p in obj.get("kill_chain_phases", []) or []
        if isinstance(p, dict)
        and p.get("kill_chain_name") == "mitre-attack"
        and p.get("phase_name")
    ]
    is_sub = bool(obj.get("x_mitre_is_subtechnique")) or "." in technique_id
    return NormalizedTechnique(
        stix_id=stix_id,
        technique_id=technique_id,
        name=name,
        description=clean_text(obj.get("description")),
        tactics=tactics,
        platforms=[str(p)[:64] for p in obj.get("x_mitre_platforms", []) or []][:30],
        is_subtechnique=is_sub,
        parent_technique_id=technique_id.split(".")[0] if is_sub else None,
        url=safe_url((ref or {}).get("url")),
        deprecated=bool(obj.get("x_mitre_deprecated")),
        revoked=bool(obj.get("revoked")),
        source_modified_at=parse_datetime(obj.get("modified")),
        raw=obj,
    )


@dataclass
class NormalizedCapec:
    stix_id: str
    capec_id: str
    name: str
    description: str | None
    url: str | None
    status: str | None
    abstraction: str | None
    likelihood: str | None
    typical_severity: str | None
    cwe_ids: list[str]
    technique_ids: list[str]
    raw: dict[str, Any]


def parse_capec_pattern(obj: dict[str, Any]) -> NormalizedCapec:
    stix_id = obj.get("id")
    if not isinstance(stix_id, str) or not stix_id.startswith("attack-pattern--"):
        raise RecordError("not a CAPEC attack-pattern")
    refs = [r for r in obj.get("external_references", []) or [] if isinstance(r, dict)]
    capec_ref = next((r for r in refs if r.get("source_name") == "capec"), None)
    capec_id = str((capec_ref or {}).get("external_id", "")).upper()
    if not CAPEC_ID_RE.match(capec_id):
        raise RecordError(f"{stix_id}: missing CAPEC ID")
    name = clean_text(obj.get("name"), MAX_SHORT)
    if not name:
        raise RecordError(f"{capec_id}: missing name")
    cwe_ids = sorted(
        {
            c
            for c in (
                normalize_cwe_id(r.get("external_id"))
                for r in refs
                if r.get("source_name") == "cwe"
            )
            if c
        }
    )
    techniques: set[str] = set()
    for r in refs:
        if r.get("source_name") != "ATTACK":
            continue
        tid = str(r.get("external_id", "")).strip().upper()
        tid = tid if tid.startswith("T") else f"T{tid}"
        if TECHNIQUE_ID_RE.match(tid):
            techniques.add(tid)
    status = clean_text(obj.get("x_capec_status"), 16)
    if obj.get("revoked"):
        status = "Revoked"
    return NormalizedCapec(
        stix_id=stix_id,
        capec_id=capec_id,
        name=name,
        description=clean_text(obj.get("description")),
        url=safe_url((capec_ref or {}).get("url")),
        status=status,
        abstraction=clean_text(obj.get("x_capec_abstraction"), 16),
        likelihood=clean_text(obj.get("x_capec_likelihood_of_attack"), 16),
        typical_severity=clean_text(obj.get("x_capec_typical_severity"), 16),
        cwe_ids=cwe_ids,
        technique_ids=sorted(techniques),
        raw=obj,
    )
