"""Dependency analysis against seeded OSV and CVE data."""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.db.models import AffectedProduct, Vulnerability
from app.dependencies.matcher import analyze
from app.dependencies.parsers import parse_manifest
from app.main import create_app
from tests.integration.helpers import FakeUpstream, seed_fixture_data, source_settings

pytestmark = pytest.mark.integration


@pytest.fixture
def seeded(database_url: str, session_factory: Any) -> Any:
    settings = source_settings(database_url)
    seed_fixture_data(settings, session_factory, FakeUpstream())
    return settings


def run(db: Session, filename: str, text: str, client: Any = None) -> Any:
    return analyze(db, parse_manifest(filename, text.encode()), client)


def test_confirmed_match_with_fix_and_alias(seeded: Any, db: Session) -> None:
    report = run(db, "requirements.txt", "flask==2.2.4\n")

    [finding] = report.findings
    assert finding.confidence == "confirmed" and finding.advisory_id == "GHSA-m2qf-hxjv-5gpq"
    assert finding.cve_ids == ["CVE-2023-30861"] and finding.severity == "HIGH"
    assert finding.fixed_versions == ["2.2.5", "2.3.2"]
    assert "PYSEC-2023-62" in finding.reason  # alias noted, not duplicated
    assert report.vulnerable_packages == 1
    assert report.summary["confirmed_by_severity"] == {"HIGH": 1}


def test_fixed_versions_are_not_reported(seeded: Any, db: Session) -> None:
    for version in ("2.2.5", "2.3.2", "3.0.0"):
        assert run(db, "requirements.txt", f"flask=={version}\n").findings == []


def test_osv_coverage_suppresses_cve_record_fallback(seeded: Any, db: Session) -> None:
    # The CVE record for CVE-2023-30861 names product "flask"; OSV covers it, so a
    # fixed version must not resurface through the name-only fallback.
    report = run(db, "requirements.txt", "flask==2.2.5\n")
    assert report.findings == []


def test_unpinned_is_uncertain(seeded: Any, db: Session) -> None:
    report = run(db, "requirements.txt", "flask>=2.0\n")
    [finding] = report.findings
    assert finding.confidence == "uncertain" and "not pinned" in finding.reason
    assert report.vulnerable_packages == 0
    assert report.unpinned_count == 1


def test_specifier_excluding_affected_versions(seeded: Any, db: Session) -> None:
    # The flask advisory enumerates affected versions; >=3.0 contains none of them.
    assert run(db, "requirements.txt", "flask>=3.0\n").findings == []


def test_cve_record_fallback_is_uncertain(seeded: Any, session_factory: Any, db: Session) -> None:
    with session_factory.begin() as session:
        vuln = Vulnerability(cve_id="CVE-2099-0004", state="PUBLISHED", title="Synthetic")
        session.add(vuln)
        session.flush()
        session.add(
            AffectedProduct(
                vulnerability_id=vuln.id,
                ingest_source="cve5",
                provider="test",
                vendor="n/a",
                product="examplepkg",
                cpes=[],
                versions=[{"version": "< 1.2.0", "status": "affected"}],
            )
        )
    report = run(db, "requirements.txt", "examplepkg==1.1.0\nexamplepkg-other==1.0\n")
    [finding] = report.findings
    assert (finding.confidence, finding.cve_ids) == ("uncertain", ["CVE-2099-0004"])
    assert "inside the stated range" in finding.reason
    assert run(db, "requirements.txt", "examplepkg==1.2.0\n").findings == []


def test_ecosystem_mismatch_is_not_matched(seeded: Any, db: Session) -> None:
    lock = {"lockfileVersion": 3, "packages": {"node_modules/flask": {"version": "2.2.4"}}}
    report = run(db, "package-lock.json", json.dumps(lock))
    assert report.findings == []  # the OSV advisory is for PyPI flask, not npm


def test_online_osv_supplements_local_data(seeded: Any, db: Session) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["queries"][0]["package"] == {"name": "flask", "ecosystem": "PyPI"}
        return httpx.Response(
            200,
            json={
                "results": [
                    {
                        "vulns": [
                            {"id": "GHSA-m2qf-hxjv-5gpq"},
                            {"id": "GHSA-new0-0000-0000"},
                            {"id": "MAL-2024-1"},
                        ]
                    }
                ]
            },
        )

    client = httpx.Client(base_url="https://osv.test/v1", transport=httpx.MockTransport(handler))
    report = run(db, "requirements.txt", "flask==2.2.4\n", client)
    ids = [f.advisory_id for f in report.findings]
    assert ids == ["GHSA-m2qf-hxjv-5gpq", "GHSA-new0-0000-0000"]  # no duplicate, no MAL
    assert "OSV.dev API" in report.sources

    down = httpx.Client(
        base_url="https://osv.test/v1", transport=httpx.MockTransport(lambda r: httpx.Response(503))
    )
    degraded = run(db, "requirements.txt", "flask==2.2.4\n", down)
    assert len(degraded.findings) == 1 and "OSV.dev lookup failed" in degraded.warnings[0]


@pytest.fixture
def client(seeded: Any) -> Iterator[TestClient]:
    with TestClient(create_app(seeded)) as test_client:
        yield test_client


URL = "/api/v1/dependencies/analyze"


def test_upload_api(client: TestClient) -> None:
    response = client.post(URL, files={"file": ("requirements.txt", b"flask==2.2.4\n")})
    body = response.json()
    assert response.status_code == 200
    assert body["filename"] == "requirements.txt" and len(body["sha256"]) == 64
    assert body["findings"][0]["confidence"] == "confirmed"


def test_upload_errors(client: TestClient) -> None:
    def post(name: str, content: bytes) -> httpx.Response:
        return client.post(URL, files={"file": (name, content)})

    assert post("setup.py", b"print(1)").status_code == 415
    assert post("requirements.txt", b"").status_code == 422
    assert post("package.json", b"{bad").status_code == 422
    assert post("requirements.txt", b"a" * (512 * 1024 + 1)).status_code == 413
    traversal = post("../../package.json", b"{}")
    assert traversal.status_code == 200 and traversal.json()["filename"] == "package.json"
    assert client.post(URL).status_code == 422  # no file


def test_upload_rate_limit(database_url: str, seeded: Any) -> None:
    app = create_app(source_settings(database_url, rate_limit_dependencies_per_minute=1))
    with TestClient(app) as client:
        first = client.post(URL, files={"file": ("requirements.txt", b"flask==2.2.4\n")})
        second = client.post(URL, files={"file": ("requirements.txt", b"flask==2.2.4\n")})
    assert (first.status_code, second.status_code) == (200, 429)
