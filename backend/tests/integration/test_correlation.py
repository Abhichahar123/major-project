"""Correlation rules against seeded fixture data plus targeted synthetic rows."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import update
from sqlalchemy.orm import Session

from app.correlation.rules import RULES
from app.correlation.service import (
    chain_from_cwes,
    correlate_vulnerability,
    cwe_overview,
    technique_vulnerabilities,
)
from app.db.models import (
    AffectedProduct,
    AttackTechnique,
    CapecAttackMapping,
    CapecPattern,
    Vulnerability,
    VulnerabilityCwe,
)
from app.main import create_app
from tests.integration.helpers import FakeUpstream, seed_fixture_data, source_settings

pytestmark = pytest.mark.integration


@pytest.fixture
def seeded(database_url: str, session_factory: Any) -> Any:
    settings = source_settings(database_url)
    seed_fixture_data(settings, session_factory, FakeUpstream())
    return settings


def test_every_rule_is_documented_and_typed() -> None:
    assert {r.kind for r in RULES.values()} == {"authoritative", "inferred"}
    assert RULES["cve_cwe_capec_attack_chain"].kind == "inferred"
    assert all(r.limitations for r in RULES.values())


def test_flask_chain_to_attack_with_paths(seeded: Any, db: Session) -> None:
    result = correlate_vulnerability(db, "CVE-2023-30861")
    assert result is not None

    [weakness] = result["weaknesses"]
    assert weakness["cwe_id"] == "CWE-539" and weakness["stated_by"] == ["GitHub_M"]
    assert weakness["relationship"] == "authoritative"
    assert [p["capec_id"] for p in result["attack_patterns"]] == ["CAPEC-21"]
    t1539 = next(t for t in result["techniques"] if t["technique_id"] == "T1539")
    assert t1539["relationship"] == "inferred" and t1539["rule"] == "cve_cwe_capec_attack_chain"
    assert t1539["paths"] == [
        {
            "cwe_id": "CWE-539",
            "capec_id": "CAPEC-21",
            "capec_name": "Exploitation of Trusted Identifiers",
        }
    ]
    assert t1539["confidence"] == "low"  # a single path
    assert [a["id"] for a in result["advisories"]] == ["GHSA-m2qf-hxjv-5gpq"]
    assert result["kev"]["listed"] is False


def test_technique_missing_from_attack_dataset_is_marked(
    seeded: Any, session_factory: Any, db: Session
) -> None:
    # A CAPEC mapping to a technique that is not in the ingested ATT&CK data.
    with session_factory.begin() as session:
        session.add(CapecAttackMapping(capec_id="CAPEC-21", technique_id="T1999"))
    result = correlate_vulnerability(db, "CVE-2023-30861")
    assert result is not None
    [unknown] = [t for t in result["techniques"] if not t["in_attack_dataset"]]
    assert unknown["technique_id"] == "T1999" and unknown["name"] is None


def test_kev_and_broad_cwe_handling(seeded: Any, db: Session) -> None:
    result = correlate_vulnerability(db, "CVE-2021-44228")
    assert result is not None
    assert result["kev"]["listed"] is True and result["kev"]["relationship"] == "authoritative"
    stated = {w["cwe_id"]: w["stated_by"] for w in result["weaknesses"]}
    assert "CISA KEV" in stated["CWE-502"]  # KEV also lists the CWE
    for technique in result["techniques"]:
        if set(technique["supporting_cwes"]) <= {"CWE-20", "CWE-400"}:
            assert technique["via_broad_cwe_only"] and technique["confidence"] == "low"


def test_kev_only_cve(seeded: Any, db: Session) -> None:
    result = correlate_vulnerability(db, "CVE-2023-4966")
    assert result is not None and result["record_available"] is False
    assert result["kev"]["listed"] is True
    assert any("not ingested" in n for n in result["notes"])


def test_unknown_cve_returns_none(seeded: Any, db: Session) -> None:
    assert correlate_vulnerability(db, "CVE-1999-0001") is None


def test_cve_without_cwe_explains_missing_chain(
    seeded: Any, session_factory: Any, db: Session
) -> None:
    with session_factory.begin() as session:
        session.add(
            Vulnerability(
                cve_id="CVE-2099-0002",
                state="PUBLISHED",
                description="Synthetic record without CWE.",
            )
        )
    result = correlate_vulnerability(db, "CVE-2099-0002")
    assert result is not None and result["weaknesses"] == [] and result["techniques"] == []
    assert any("No CWE is assigned" in n for n in result["notes"])


def test_deprecated_patterns_and_revoked_techniques_are_skipped(
    seeded: Any, session_factory: Any, db: Session
) -> None:
    with session_factory.begin() as session:
        session.execute(
            update(CapecPattern)
            .where(CapecPattern.capec_id == "CAPEC-21")
            .values(status="Deprecated")
        )
    chain = chain_from_cwes(db, {"CWE-539"})
    assert chain["patterns"] == [] and chain["techniques"] == []
    assert any("deprecated" in n for n in chain["notes"])

    with session_factory.begin() as session:
        session.execute(
            update(CapecPattern).where(CapecPattern.capec_id == "CAPEC-21").values(status="Draft")
        )
        session.execute(
            update(AttackTechnique)
            .where(AttackTechnique.technique_id == "T1539")
            .values(revoked=True)
        )
    chain = chain_from_cwes(db, {"CWE-539"})
    assert "T1539" not in [t["technique_id"] for t in chain["techniques"]]
    assert any("T1539" in n for n in chain["notes"])


def test_duplicate_mappings_do_not_duplicate_paths(
    seeded: Any, session_factory: Any, db: Session
) -> None:
    # CWE stated by two providers must still give one path per (CWE, CAPEC).
    with session_factory.begin() as session:
        vid = session.query(Vulnerability.id).filter_by(cve_id="CVE-2023-30861").scalar()
        session.add(
            VulnerabilityCwe(
                vulnerability_id=vid, cwe_id="CWE-539", ingest_source="nvd", provider="nvd@nist.gov"
            )
        )
    result = correlate_vulnerability(db, "CVE-2023-30861")
    assert result is not None
    t1539 = next(t for t in result["techniques"] if t["technique_id"] == "T1539")
    assert len(t1539["paths"]) == 1
    assert result["weaknesses"][0]["stated_by"] == ["GitHub_M", "nvd@nist.gov"]


def test_shared_product_relation(seeded: Any, session_factory: Any, db: Session) -> None:
    with session_factory.begin() as session:
        other = Vulnerability(cve_id="CVE-2099-0003", state="PUBLISHED", title="Other flask bug")
        session.add(other)
        session.flush()
        session.add(
            AffectedProduct(
                vulnerability_id=other.id,
                ingest_source="test",
                provider="test",
                vendor="Pallets",
                product="Flask",
                cpes=[],
                versions=[],
            )
        )
    result = correlate_vulnerability(db, "CVE-2023-30861")
    assert result is not None
    [related] = result["related_vulnerabilities"]
    assert related["cve_id"] == "CVE-2099-0003"
    assert related["reasons"] == [{"rule": "shared_product", "shared": "pallets flask"}]
    assert related["relationship"] == "inferred"


def test_technique_to_vulnerabilities(seeded: Any, db: Session) -> None:
    result = technique_vulnerabilities(db, "T1539")
    assert result is not None
    assert [c["capec_id"] for c in result["capec_patterns"]] == ["CAPEC-21"]
    [vuln] = result["vulnerabilities"]
    assert vuln["cve_id"] == "CVE-2023-30861" and vuln["relationship"] == "inferred"
    assert technique_vulnerabilities(db, "T9999") is None


def test_unsupported_link_is_not_invented(seeded: Any, session_factory: Any, db: Session) -> None:
    # A CAPEC->ATT&CK mapping alone (no CWE path from the CVE) must not link the CVE.
    with session_factory.begin() as session:
        session.add(CapecAttackMapping(capec_id="CAPEC-586", technique_id="T1190"))
    result = correlate_vulnerability(db, "CVE-2023-30861")
    assert result is not None
    assert "T1190" not in [t["technique_id"] for t in result["techniques"]]


def test_cwe_overview(seeded: Any, db: Session) -> None:
    overview = cwe_overview(db, "CWE-539")
    assert overview is not None and overview["vulnerability_count"] == 1
    assert overview["url"].endswith("/539.html")
    assert cwe_overview(db, "CWE-99999") is None


@pytest.fixture
def client(seeded: Any) -> Iterator[TestClient]:
    with TestClient(create_app(seeded)) as test_client:
        yield test_client


def test_correlation_api(client: TestClient) -> None:
    body = client.get("/api/v1/vulnerabilities/cve-2023-30861/correlations").json()
    assert body["weaknesses"][0]["cwe_id"] == "CWE-539"
    assert {r["id"] for r in body["rules"]} >= {"cve_cwe_capec_attack_chain", "kev_listing"}
    assert client.get("/api/v1/vulnerabilities/CVE-1999-0001/correlations").status_code == 404
    assert client.get("/api/v1/techniques/T1539/vulnerabilities").json()["total"] == 1
    assert client.get("/api/v1/cwes/CWE-539").status_code == 200
    assert client.get("/api/v1/cwes/XSS").status_code == 422
    rules = client.get("/api/v1/correlation/rules").json()
    assert len(rules) == len(RULES)
    # The detail route still works next to the more specific correlations route.
    assert client.get("/api/v1/vulnerabilities/CVE-2023-30861").status_code == 200
