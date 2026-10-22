"""HTTP API tests against a real database seeded through the ingestion pipeline."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from tests.integration.helpers import (
    FakeUpstream,
    http_factory_for,
    seed_fixture_data,
    source_settings,
)

pytestmark = pytest.mark.integration

ADMIN_KEY = "a" * 40


@pytest.fixture
def settings(database_url: str) -> Any:
    return source_settings(database_url, admin_api_key=ADMIN_KEY)


@pytest.fixture
def client(settings: Any, session_factory: Any) -> Iterator[TestClient]:
    upstream = FakeUpstream()
    seed_fixture_data(settings, session_factory, upstream)
    app = create_app(settings)
    with TestClient(app) as test_client:
        app.state.http_factory = http_factory_for(settings, upstream)
        yield test_client


API = "/api/v1"


# ----------------------------------------------------------------------- search


def test_search_by_text_and_filters(client: TestClient) -> None:
    body = client.get(f"{API}/vulnerabilities", params={"q": "cookie", "page_size": 5}).json()
    assert body["total"] == 1 and body["items"][0]["cve_id"] == "CVE-2023-30861"
    assert body["items"][0]["rank"] > 0

    critical = client.get(f"{API}/vulnerabilities", params={"severity": "CRITICAL"}).json()
    assert [i["cve_id"] for i in critical["items"]] == ["CVE-2021-44228"]

    kev = client.get(f"{API}/vulnerabilities", params={"in_kev": "true"}).json()
    assert [i["cve_id"] for i in kev["items"]] == ["CVE-2021-44228"]
    assert kev["items"][0]["in_kev"] is True

    by_cwe = client.get(f"{API}/vulnerabilities", params={"cwe": "CWE-539"}).json()
    assert [i["cve_id"] for i in by_cwe["items"]] == ["CVE-2023-30861"]

    by_product = client.get(f"{API}/vulnerabilities", params={"product": "flask"}).json()
    assert by_product["total"] == 1

    scored = client.get(f"{API}/vulnerabilities", params={"min_cvss": 9.5}).json()
    assert [i["cve_id"] for i in scored["items"]] == ["CVE-2021-44228"]


def test_search_by_cve_id_and_prefix(client: TestClient) -> None:
    exact = client.get(f"{API}/vulnerabilities", params={"q": "cve-2021-44228"}).json()
    assert exact["total"] == 1
    prefix = client.get(f"{API}/vulnerabilities", params={"q": "CVE-2023"}).json()
    assert [i["cve_id"] for i in prefix["items"]] == ["CVE-2023-30861"]


def test_search_pagination(client: TestClient) -> None:
    first = client.get(f"{API}/vulnerabilities", params={"page_size": 1, "sort": "cvss"}).json()
    second = client.get(
        f"{API}/vulnerabilities", params={"page_size": 1, "page": 2, "sort": "cvss"}
    ).json()
    assert first["total"] == second["total"] == 2
    assert first["items"][0]["cve_id"] == "CVE-2021-44228"
    assert second["items"][0]["cve_id"] == "CVE-2023-30861"


@pytest.mark.parametrize(
    "params",
    [
        {"page_size": 101},
        {"page": 0},
        {"severity": "SEVERE"},
        {"min_cvss": 11},
        {"cwe": "79"},
        {"q": "x" * 201},
        {"min_cvss": 9, "max_cvss": 2},
        {"sort": "random"},
    ],
)
def test_search_validation(client: TestClient, params: dict[str, Any]) -> None:
    response = client.get(f"{API}/vulnerabilities", params=params)
    assert response.status_code == 422
    assert response.headers["content-type"] == "application/problem+json"


def test_search_text_with_sql_metacharacters_is_safe(client: TestClient) -> None:
    for q in ["'; DROP TABLE vulnerabilities; --", "100%", "a_b", "\\"]:
        response = client.get(f"{API}/vulnerabilities", params={"q": q, "vendor": q})
        assert response.status_code == 200
    assert client.get(f"{API}/vulnerabilities").json()["total"] == 2


# ----------------------------------------------------------------------- detail


def test_detail_includes_provenance_and_advisories(client: TestClient) -> None:
    body = client.get(f"{API}/vulnerabilities/CVE-2023-30861").json()

    assert body["record_available"] is True
    assert body["severity"] == "HIGH" and body["cvss_provider"] == "GitHub_M"
    assert body["cvss"][0]["provider"] == "GitHub_M"
    assert [c["cwe_id"] for c in body["cwes"]] == ["CWE-539"]
    assert body["affected"][0]["product"] == "flask"
    assert [a["id"] for a in body["advisories"]] == ["GHSA-m2qf-hxjv-5gpq"]
    assert body["advisories"][0]["packages"][0]["fixed_versions"] == ["2.2.5", "2.3.2"]
    assert {p["source"] for p in body["provenance"]} == {"cve5"}
    assert body["kev"] is None
    assert "CNA first" in body["severity_rule"]


def test_detail_for_kev_only_cve(client: TestClient) -> None:
    body = client.get(f"{API}/vulnerabilities/CVE-2023-4966").json()
    assert body["record_available"] is False
    assert body["kev"]["vendor_project"] == "Citrix"


def test_detail_errors(client: TestClient) -> None:
    missing = client.get(f"{API}/vulnerabilities/CVE-1999-0001")
    assert missing.status_code == 404 and missing.json()["code"] == "cve_not_found"
    invalid = client.get(f"{API}/vulnerabilities/CVE-21-1")
    assert invalid.status_code == 422


# ------------------------------------------------------------------ KEV / ATT&CK


def test_kev_listing_and_filters(client: TestClient) -> None:
    body = client.get(f"{API}/kev").json()
    assert body["total"] == 3
    dates = [i["date_added"] for i in body["items"]]
    assert dates == sorted(dates, reverse=True)
    log4j = next(i for i in body["items"] if i["cve_id"] == "CVE-2021-44228")
    assert log4j["has_cve_record"] is True and log4j["severity"] == "CRITICAL"

    citrix = client.get(f"{API}/kev", params={"vendor": "citrix"}).json()
    assert [i["cve_id"] for i in citrix["items"]] == ["CVE-2023-4966"]
    known = client.get(f"{API}/kev", params={"ransomware": "Known"}).json()
    assert all(i["known_ransomware_use"] == "Known" for i in known["items"])
    assert client.get(f"{API}/kev", params={"ransomware": "maybe"}).status_code == 422


def test_techniques(client: TestClient) -> None:
    listing = client.get(f"{API}/techniques", params={"tactic": "initial-access"}).json()
    assert "T1190" in [t["technique_id"] for t in listing["items"]]
    revoked_hidden = client.get(f"{API}/techniques").json()
    assert not any(t["revoked"] for t in revoked_hidden["items"])

    detail = client.get(f"{API}/techniques/t1059").json()
    assert detail["name"] == "Command and Scripting Interpreter"
    assert "T1059.001" in [s["technique_id"] for s in detail["subtechniques"]]
    assert client.get(f"{API}/techniques/T9999").status_code == 404
    assert client.get(f"{API}/techniques/X1").status_code == 422


# ------------------------------------------------------------- sources and stats


def test_sources_jobs_and_stats(client: TestClient) -> None:
    sources = {s["code"]: s for s in client.get(f"{API}/sources").json()}
    assert sources["kev"]["tracked_records"] == 3
    assert sources["kev"]["latest_job"]["status"] == "succeeded"
    assert sources["nvd"]["latest_job"] is None

    jobs = client.get(f"{API}/ingestion/jobs", params={"source": "cve5"}).json()
    assert jobs["total"] == 1
    job = client.get(f"{API}/ingestion/jobs/{jobs['items'][0]['id']}").json()
    assert "errors" not in job  # per-record errors are admin-only

    stats = client.get(f"{API}/stats").json()
    assert (stats["vulnerabilities"], stats["kev_entries"], stats["kev_with_cve_record"]) == (
        2,
        3,
        1,
    )
    assert stats["advisories"] == 1
    assert {s["key"] for s in stats["by_severity"]} == {"CRITICAL", "HIGH"}


def test_readiness(client: TestClient) -> None:
    for path in ("/health/ready", f"{API}/health/ready"):
        body = client.get(path).json()
        assert body["status"] in {"ok", "degraded"}
        assert body["checks"]["database"]["status"] == "ok"
        assert body["checks"]["migrations"]["status"] == "ok"
        assert body["checks"]["pgvector"]["status"] == "ok"


# ------------------------------------------------------------------------ admin


def test_admin_requires_valid_key(client: TestClient) -> None:
    url = f"{API}/admin/ingestion/jobs"
    assert client.post(url, json={"source": "kev"}).status_code == 401
    wrong = client.post(url, json={"source": "kev"}, headers={"X-Admin-Key": "b" * 40})
    assert wrong.status_code == 403 and ADMIN_KEY not in wrong.text


def test_admin_job_runs_in_background(client: TestClient) -> None:
    headers = {"X-Admin-Key": ADMIN_KEY}
    accepted = client.post(
        f"{API}/admin/ingestion/jobs", headers=headers, json={"source": "kev", "params": {}}
    )
    assert accepted.status_code == 202
    job_id = accepted.json()["job_id"]
    # TestClient runs background tasks before returning, so the job has finished.
    detail = client.get(f"{API}/admin/ingestion/jobs/{job_id}", headers=headers).json()
    assert detail["status"] == "succeeded" and detail["records_unchanged"] == 3
    assert detail["errors"] == []


def test_admin_rejects_bad_params_and_unknown_sources(client: TestClient) -> None:
    headers = {"X-Admin-Key": ADMIN_KEY}
    url = f"{API}/admin/ingestion/jobs"
    bad = client.post(url, headers=headers, json={"source": "cve5", "params": {"mode": "all"}})
    assert bad.status_code == 422 and bad.json()["code"] == "invalid_job_params"
    unknown = client.post(url, headers=headers, json={"source": "shodan"})
    assert unknown.status_code == 422
    smuggled = client.post(
        url, headers=headers, json={"source": "kev", "params": {"url": "https://evil.example"}}
    )
    assert smuggled.status_code == 422


def test_admin_disabled_without_key(database_url: str, session_factory: Any) -> None:
    app = create_app(source_settings(database_url))
    with TestClient(app) as client:
        response = client.post(
            f"{API}/admin/ingestion/jobs",
            json={"source": "kev"},
            headers={"X-Admin-Key": "anything"},
        )
    assert response.status_code == 503 and response.json()["code"] == "admin_disabled"


def test_rate_limit(database_url: str, session_factory: Any) -> None:
    app = create_app(source_settings(database_url, rate_limit_search_per_minute=3))
    with TestClient(app) as client:
        codes = [client.get(f"{API}/kev").status_code for _ in range(4)]
    assert codes == [200, 200, 200, 429]
