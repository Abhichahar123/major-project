"""Unit tests for record normalization, using real records saved as fixtures.

Fixtures are verbatim CVE Program, CISA KEV, MITRE ATT&CK and CAPEC data, except
``nvd_synthetic_page.json``, which is synthetic data in the NVD API format.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from app.ingestion.normalize import (
    CvssScore,
    RecordError,
    content_hash,
    cve5_record_path,
    parse_attack_technique,
    parse_capec_pattern,
    parse_cve5,
    parse_kev_catalog,
    parse_kev_entry,
    parse_nvd,
    safe_url,
    select_display_cvss,
    severity_from_score,
    stix_objects,
)

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text())


def test_cve5_cna_record_is_normalized() -> None:
    vuln = parse_cve5(load("CVE-2023-30861.json"))

    assert vuln.cve_id == "CVE-2023-30861"
    assert vuln.state == "PUBLISHED"
    assert vuln.assigner == "GitHub_M"
    assert vuln.description and "Flask" in vuln.description
    assert vuln.published_at and vuln.published_at.year == 2023
    [score] = [s for s in vuln.cvss if s.provider == "GitHub_M"]
    assert (score.version, score.base_score, score.base_severity) == ("3.1", 7.5, "HIGH")
    assert score.provider_rank == 0
    assert (
        "CWE-539",
        "GitHub_M",
        "Use of Persistent Cookies Containing Sensitive Information",
    ) in vuln.cwes
    [flask] = vuln.affected
    assert (flask.vendor, flask.product) == ("pallets", "flask")
    assert {"version": ">= 2.3.0, < 2.3.2", "status": "affected"} in flask.versions
    assert any("GHSA-m2qf-hxjv-5gpq" in r.url for r in vuln.references)


def test_cve5_adp_scores_are_kept_with_their_provider() -> None:
    vuln = parse_cve5(load("CVE-2021-44228.json"))

    adp = [s for s in vuln.cvss if s.provider == "CISA-ADP"]
    assert adp and adp[0].base_score == 10.0 and adp[0].provider_rank == 2
    # The CNA gave no CVSS, so the display score falls back to CISA-ADP.
    display = select_display_cvss(vuln.cvss)
    assert display is not None and display.provider == "CISA-ADP"
    assert {c[0] for c in vuln.cwes} >= {"CWE-502", "CWE-400", "CWE-20"}


def test_display_cvss_precedence() -> None:
    scores = [
        CvssScore("CISA-ADP", "3.1", 9.8, "CRITICAL", None, 2),
        CvssScore("vendor", "4.0", 8.7, "HIGH", None, 0),
        CvssScore("vendor", "3.1", 8.1, "HIGH", None, 0),
        CvssScore("nvd@nist.gov", "3.1", 7.5, "HIGH", None, 1),
    ]
    best = select_display_cvss(scores)
    assert best is not None and (best.provider, best.version) == ("vendor", "3.1")
    assert select_display_cvss([]) is None


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.update(dataType="SOMETHING_ELSE"),
        lambda r: r["cveMetadata"].update(cveId="CVE-21-1"),
        lambda r: r["cveMetadata"].update(state="RESERVED"),
    ],
)
def test_invalid_cve5_records_raise(mutate: Any) -> None:
    record = copy.deepcopy(load("CVE-2023-30861.json"))
    mutate(record)
    with pytest.raises(RecordError):
        parse_cve5(record)


def test_cve5_placeholders_and_bad_urls_are_dropped() -> None:
    record = copy.deepcopy(load("CVE-2023-30861.json"))
    cna = record["containers"]["cna"]
    cna["affected"] = [
        {"vendor": "n/a", "product": "n/a", "versions": [{"version": "n/a", "status": "affected"}]}
    ]
    cna["references"] = [
        {"url": "javascript:alert(1)"},
        {"url": "ftp://x"},
        {"url": "https://ok.example/a"},
    ]
    cna["descriptions"][0]["value"] = "text with NUL\x00 and bell\x07 removed"

    vuln = parse_cve5(record)

    assert vuln.affected == []  # nothing identifiable remains
    urls = [r.url for r in vuln.references]
    assert "https://ok.example/a" in urls
    assert not any(u.startswith(("javascript:", "ftp:")) for u in urls)
    assert vuln.description == "text with NUL and bell removed"


def test_rejected_record_uses_rejected_reason() -> None:
    record = copy.deepcopy(load("CVE-2023-30861.json"))
    record["cveMetadata"]["state"] = "REJECTED"
    record["containers"]["cna"]["rejectedReasons"] = [
        {"lang": "en", "value": "Duplicate of another CVE."}
    ]

    vuln = parse_cve5(record)

    assert vuln.state == "REJECTED"
    assert vuln.description == "Duplicate of another CVE."


def test_nvd_record_is_normalized_from_synthetic_fixture() -> None:
    item = load("nvd_synthetic_page.json")["vulnerabilities"][0]

    vuln = parse_nvd(item)

    assert vuln.cve_id == "CVE-2023-30861"
    assert vuln.description and vuln.description.startswith("Synthetic NVD description")
    primary = [s for s in vuln.cvss if s.provider == "nvd@nist.gov" and s.version == "3.1"]
    assert primary[0].provider_rank == 1
    v2 = next(s for s in vuln.cvss if s.version == "2.0")
    assert v2.base_severity == "MEDIUM"  # derived from the 5.0 score when absent
    assert [c[0] for c in vuln.cwes] == ["CWE-539"]  # NVD-CWE-noinfo is skipped
    [flask] = vuln.affected
    assert (flask.vendor, flask.product) == ("palletsprojects", "flask")
    assert {"status": "affected", "versionType": "cpe", "lessThan": "2.2.5"} in flask.versions
    assert all(r.url.startswith("https://") for r in vuln.references)


def test_kev_catalog_and_entry() -> None:
    version, entries = parse_kev_catalog(load("kev_sample.json"))
    assert version and entries

    kev = parse_kev_entry(next(e for e in entries if e["cveID"] == "CVE-2021-44228"))

    assert kev.vendor_project == "Apache"
    assert kev.date_added.isoformat() == "2021-12-10"
    assert kev.known_ransomware_use in {"Known", "Unknown"}


def test_kev_entry_missing_fields_raises() -> None:
    entry = copy.deepcopy(load("kev_sample.json")["vulnerabilities"][0])
    entry["dateAdded"] = "not-a-date"
    with pytest.raises(RecordError, match="dateAdded"):
        parse_kev_entry(entry)
    with pytest.raises(RecordError):
        parse_kev_entry({"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"})


def test_attack_techniques_parse() -> None:
    objects = stix_objects(load("attack_sample.json"))
    patterns = [o for o in objects if o["type"] == "attack-pattern"]
    parsed = {t.technique_id: t for t in map(parse_attack_technique, patterns)}

    assert "T1190" in parsed and "initial-access" in parsed["T1190"].tactics
    sub = parsed["T1059.001"]
    assert sub.is_subtechnique and sub.parent_technique_id == "T1059"
    assert any(t.revoked for t in parsed.values())


def test_capec_mappings_parse() -> None:
    objects = stix_objects(load("capec_sample.json"))
    parsed = {p.capec_id: p for p in map(parse_capec_pattern, objects)}

    assert "CWE-539" in parsed["CAPEC-21"].cwe_ids
    assert "T1539" in parsed["CAPEC-21"].technique_ids
    assert all(t.startswith("T") for p in parsed.values() for t in p.technique_ids)


def test_stix_objects_rejects_non_bundles() -> None:
    with pytest.raises(RecordError):
        stix_objects({"type": "not-a-bundle"})


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.0, "NONE"),
        (3.9, "LOW"),
        (4.0, "MEDIUM"),
        (6.9, "MEDIUM"),
        (7.0, "HIGH"),
        (9.0, "CRITICAL"),
    ],
)
def test_severity_from_score(score: float, expected: str) -> None:
    assert severity_from_score(score) == expected


def test_cve5_record_path_handles_long_ids() -> None:
    assert cve5_record_path("CVE-2021-44228") == "2021/44xxx/CVE-2021-44228.json"
    assert cve5_record_path("CVE-2026-106931") == "2026/106xxx/CVE-2026-106931.json"
    assert cve5_record_path("CVE-2024-0001") == "2024/0xxx/CVE-2024-0001.json"


def test_content_hash_is_key_order_independent() -> None:
    assert content_hash({"a": 1, "b": [1, 2]}) == content_hash({"b": [1, 2], "a": 1})
    assert content_hash({"a": 1}) != content_hash({"a": 2})


def test_safe_url() -> None:
    assert safe_url("https://example.org/x") == "https://example.org/x"
    assert safe_url("javascript:alert(1)") is None
    assert safe_url("https://" + "a" * 3000) is None
