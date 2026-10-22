"""Ingestion against a real database with mocked upstream sources."""

from __future__ import annotations

import copy
import io
import json
import zipfile
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.db.models import (
    Advisory,
    AttackTechnique,
    CapecAttackMapping,
    CvssMetric,
    IngestionError,
    IngestionJob,
    KevEntry,
    Source,
    Vulnerability,
    VulnerabilityCwe,
)
from app.ingestion.http import SourceHttpClient
from app.ingestion.jobs import JobConflictError, create_job, run_now
from app.ingestion.sources import (
    AttackAdapter,
    CapecAdapter,
    Cve5Adapter,
    KevAdapter,
    NvdAdapter,
    OsvAdapter,
    ParamError,
)
from tests.conftest import make_settings

pytestmark = pytest.mark.integration

from tests.integration.helpers import (  # noqa: E402
    ATTACK,
    CAPEC,
    CVE5,
    KEV_MIRROR,
    KEV_PRIMARY,
    NVD,
    OSV_BASE,
    FakeUpstream,
    fixture,
)


def recent() -> str:
    """A window start inside one 120-day NVD window, so the mock page is served once."""
    return (datetime.now(UTC) - timedelta(days=3)).isoformat()


def test_nvd_long_window_is_split(run, upstream: FakeUpstream) -> None:  # type: ignore[no-untyped-def]
    upstream.set_json(NVD, {"vulnerabilities": [], "totalResults": 0})
    run(
        NvdAdapter(sleep=lambda s: None),
        {"mode": "modified", "modified_since": "2024-01-01T00:00:00Z"},
    )
    windows = [r.url.params for r in upstream.calls if str(r.url).startswith(NVD)]
    assert len(windows) > 1
    for params in windows:
        start = datetime.fromisoformat(params["lastModStartDate"])
        end = datetime.fromisoformat(params["lastModEndDate"])
        assert end - start <= timedelta(days=120)


@pytest.fixture
def upstream() -> FakeUpstream:
    return FakeUpstream()


@pytest.fixture
def settings(database_url: str) -> Settings:
    return make_settings(
        database_url=database_url,
        kev_feed_urls=[KEV_PRIMARY, KEV_MIRROR],
        cve5_base_url=CVE5,
        nvd_api_url=NVD,
        attack_stix_url=ATTACK,
        capec_stix_url=CAPEC,
        ingestion_max_retries=1,
        ingestion_backoff_base_seconds=0,
    )


@pytest.fixture
def run(settings: Settings, session_factory: sessionmaker[Session], upstream: FakeUpstream):  # type: ignore[no-untyped-def]
    def http_factory() -> SourceHttpClient:
        return SourceHttpClient(
            allowed_hosts=settings.ingestion_allowed_hosts,
            transport=httpx.MockTransport(upstream.handler),
            max_retries=settings.ingestion_max_retries,
            backoff_base_seconds=0,
            sleep=lambda s: None,
        )

    def _run(adapter: Any, params: dict[str, Any] | None = None) -> IngestionJob:
        return run_now(adapter, params or {}, settings, session_factory, http_factory)

    return _run


def count(db: Session, model: Any) -> int:
    return db.scalar(select(func.count()).select_from(model)) or 0


# --------------------------------------------------------------------------- KEV


def test_kev_ingestion_is_idempotent(run, db: Session) -> None:  # type: ignore[no-untyped-def]
    first = run(KevAdapter())
    second = run(KevAdapter())

    assert (first.status, first.records_inserted) == ("succeeded", 3)
    assert (second.records_inserted, second.records_updated, second.records_unchanged) == (0, 0, 3)
    assert count(db, KevEntry) == 3
    source = db.scalar(select(Source).where(Source.code == "kev"))
    assert source is not None and source.last_success_at is not None


def test_kev_changed_entry_is_updated(run, upstream: FakeUpstream, db: Session) -> None:  # type: ignore[no-untyped-def]
    run(KevAdapter())
    catalog = copy.deepcopy(fixture("kev_sample.json"))
    catalog["vulnerabilities"][0]["requiredAction"] = (
        "Apply updates per vendor instructions (revised)."
    )
    upstream.set_json(KEV_PRIMARY, catalog)

    job = run(KevAdapter())

    assert (job.records_updated, job.records_unchanged) == (1, 2)
    changed = db.get(KevEntry, catalog["vulnerabilities"][0]["cveID"])
    assert changed is not None and changed.required_action.endswith("(revised).")


def test_kev_falls_back_to_mirror(run, upstream: FakeUpstream) -> None:  # type: ignore[no-untyped-def]
    upstream.set_status(KEV_PRIMARY, 503)
    upstream.set_json(KEV_MIRROR, fixture("kev_sample.json"))

    job = run(KevAdapter())

    assert job.status == "succeeded"
    assert job.details["feed_url"] == KEV_MIRROR


def test_kev_malformed_entry_gives_partial_job(run, upstream: FakeUpstream, db: Session) -> None:  # type: ignore[no-untyped-def]
    catalog = copy.deepcopy(fixture("kev_sample.json"))
    catalog["vulnerabilities"].append({"cveID": "NOT-A-CVE", "dateAdded": "2024-01-01"})
    upstream.set_json(KEV_PRIMARY, catalog)

    job = run(KevAdapter())

    assert job.status == "partial"
    assert (job.records_inserted, job.records_failed) == (3, 1)
    [error] = db.scalars(select(IngestionError).where(IngestionError.job_id == job.id)).all()
    assert error.stage == "normalize" and "invalid CVE identifier" in error.message
    assert "removed" not in (job.details or {})  # removals are skipped when entries failed


def test_kev_entries_removed_upstream_are_removed(run, upstream: FakeUpstream, db: Session) -> None:  # type: ignore[no-untyped-def]
    run(KevAdapter())
    catalog = copy.deepcopy(fixture("kev_sample.json"))
    dropped = catalog["vulnerabilities"].pop()["cveID"]
    upstream.set_json(KEV_PRIMARY, catalog)

    job = run(KevAdapter())

    assert job.details["removed_ids"] == [dropped]
    assert db.get(KevEntry, dropped) is None


def test_unavailable_source_fails_job_and_keeps_existing_data(
    run, upstream: FakeUpstream, db: Session
) -> None:  # type: ignore[no-untyped-def]
    run(KevAdapter())
    upstream.set_status(KEV_PRIMARY, 503)
    upstream.set_status(KEV_MIRROR, 503)

    job = run(KevAdapter())

    assert job.status == "failed"
    assert "all KEV feeds failed" in (job.error_summary or "")
    assert count(db, KevEntry) == 3


def test_only_one_active_job_per_source(settings: Settings, session_factory) -> None:  # type: ignore[no-untyped-def]
    create_job(session_factory, settings, KevAdapter(), {}, "test")
    with pytest.raises(JobConflictError):
        create_job(session_factory, settings, KevAdapter(), {}, "test")


def test_invalid_params_are_rejected() -> None:
    with pytest.raises(ParamError):
        Cve5Adapter().validate_params({"mode": "ids", "ids": ["CVE-1"]})
    with pytest.raises(ParamError):
        Cve5Adapter().validate_params({"mode": "everything"})
    with pytest.raises(ParamError):
        KevAdapter().validate_params({"url": "https://evil.example"})
    with pytest.raises(ParamError):
        NvdAdapter().validate_params(
            {"mode": "ids", "ids": [f"CVE-2024-{i:04d}" for i in range(201)]}
        )


# ------------------------------------------------------------------- CVE records


def test_cve5_ids_ingestion_and_rerun(run, db: Session) -> None:  # type: ignore[no-untyped-def]
    params = {"mode": "ids", "ids": ["CVE-2023-30861", "CVE-2021-44228"]}
    first = run(Cve5Adapter(), params)
    second = run(Cve5Adapter(), params)

    assert (first.status, first.records_inserted) == ("succeeded", 2)
    assert second.records_unchanged == 2
    flask = db.scalar(select(Vulnerability).where(Vulnerability.cve_id == "CVE-2023-30861"))
    assert flask is not None
    assert (flask.severity, flask.cvss_base_score, flask.cvss_provider) == ("HIGH", 7.5, "GitHub_M")
    log4j = db.scalar(select(Vulnerability).where(Vulnerability.cve_id == "CVE-2021-44228"))
    assert log4j is not None and log4j.severity == "CRITICAL" and log4j.cvss_provider == "CISA-ADP"


def test_cve5_missing_record_is_reported(run, db: Session) -> None:  # type: ignore[no-untyped-def]
    job = run(Cve5Adapter(), {"mode": "ids", "ids": ["CVE-2023-30861", "CVE-2020-99999"]})

    assert job.status == "partial"
    [error] = db.scalars(select(IngestionError).where(IngestionError.job_id == job.id)).all()
    assert (error.record_key, error.stage) == ("CVE-2020-99999", "fetch")


def test_cve5_from_kev_uses_catalog(run, upstream: FakeUpstream) -> None:  # type: ignore[no-untyped-def]
    run(KevAdapter())
    job = run(Cve5Adapter(), {"mode": "from_kev", "limit": 10})
    # The KEV sample has three CVEs; only CVE-2021-44228 has a fixture record, the others
    # return 404 and are reported per record.
    assert job.details["requested"] == 3
    assert job.records_inserted == 1 and job.records_failed == 2


def test_cve5_delta_refreshes_tracked_and_advances_watermark(
    run, upstream: FakeUpstream, db: Session
) -> None:  # type: ignore[no-untyped-def]
    run(Cve5Adapter(), {"mode": "ids", "ids": ["CVE-2023-30861"]})
    upstream.set_json(
        f"{CVE5}/deltaLog.json",
        [
            {
                "fetchTime": "2999-01-01T00:00:00Z",
                "new": [{"cveId": "CVE-2099-12345"}],
                "updated": [{"cveId": "CVE-2023-30861"}],
            },
        ],
    )

    job = run(Cve5Adapter(), {"mode": "delta"})

    assert job.status == "succeeded"
    assert job.details["requested"] == 1  # untracked new CVE skipped without include_new
    source = db.scalar(select(Source).where(Source.code == "cve5"))
    assert source is not None and source.watermark == {"fetch_time": "2999-01-01T00:00:00+00:00"}


# --------------------------------------------------------------------------- NVD


def test_nvd_enrichment_adds_rows_without_overriding_cna(run, db: Session) -> None:  # type: ignore[no-untyped-def]
    run(Cve5Adapter(), {"mode": "ids", "ids": ["CVE-2023-30861"]})

    job = run(NvdAdapter(sleep=lambda s: None), {"mode": "modified", "modified_since": recent()})

    assert job.status == "succeeded"
    assert job.details["skipped_untracked"] == 1  # CVE-2099-0001 is not tracked
    vuln = db.scalar(select(Vulnerability).where(Vulnerability.cve_id == "CVE-2023-30861"))
    assert vuln is not None
    assert vuln.description and not vuln.description.startswith("Synthetic")  # CNA text kept
    assert vuln.cvss_provider == "GitHub_M"  # CNA still preferred for display
    sources = set(
        db.scalars(select(CvssMetric.ingest_source).where(CvssMetric.vulnerability_id == vuln.id))
    )
    assert sources == {"cve5", "nvd"}
    assert db.scalar(select(Vulnerability).where(Vulnerability.cve_id == "CVE-2099-0001")) is None
    nvd_source = db.scalar(select(Source).where(Source.code == "nvd"))
    assert nvd_source is not None and "last_modified_end" in (nvd_source.watermark or {})


def test_nvd_rerun_replaces_only_its_own_rows(run, db: Session) -> None:  # type: ignore[no-untyped-def]
    run(Cve5Adapter(), {"mode": "ids", "ids": ["CVE-2023-30861"]})
    params = {"mode": "modified", "modified_since": recent()}
    run(NvdAdapter(sleep=lambda s: None), params)
    before = count(db, CvssMetric)
    job = run(NvdAdapter(sleep=lambda s: None), params)

    assert job.records_unchanged == 1
    assert count(db, CvssMetric) == before
    assert count(db, VulnerabilityCwe) >= 2  # GitHub_M via cve5 and via nvd


# ------------------------------------------------------------------ ATT&CK / CAPEC


def test_attack_and_capec_ingestion(run, db: Session) -> None:  # type: ignore[no-untyped-def]
    attack = run(AttackAdapter())
    capec = run(CapecAdapter())
    again = run(AttackAdapter())

    assert attack.status == "succeeded" and attack.details["attack_version"]
    assert capec.records_inserted == 3
    assert again.records_inserted == 0
    t1190 = db.scalar(select(AttackTechnique).where(AttackTechnique.technique_id == "T1190"))
    assert t1190 is not None and "initial-access" in t1190.tactics
    mapping = db.scalar(
        select(CapecAttackMapping).where(
            CapecAttackMapping.capec_id == "CAPEC-21", CapecAttackMapping.technique_id == "T1539"
        )
    )
    assert mapping is not None


# --------------------------------------------------------------------------- OSV


def osv_zip(records: dict[str, Any], extra: dict[str, bytes] | None = None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, record in records.items():
            archive.writestr(f"{name}.json", json.dumps(record))
        for name, raw in (extra or {}).items():
            archive.writestr(name, raw)
    return buffer.getvalue()


@pytest.fixture
def osv_settings(settings: Settings) -> Settings:
    return settings.model_copy(update={"osv_data_base_url": OSV_BASE})


@pytest.fixture
def osv_run(osv_settings: Settings, session_factory, upstream: FakeUpstream):  # type: ignore[no-untyped-def]
    def http_factory() -> SourceHttpClient:
        return SourceHttpClient(
            allowed_hosts=osv_settings.ingestion_allowed_hosts,
            transport=httpx.MockTransport(upstream.handler),
            max_retries=0,
            sleep=lambda s: None,
        )

    def _run(params: dict[str, Any]) -> IngestionJob:
        return run_now(OsvAdapter(), params, osv_settings, session_factory, http_factory)

    return _run


def osv_records() -> dict[str, Any]:
    flask = fixture("osv_GHSA-m2qf-hxjv-5gpq.json")
    return {
        flask["id"]: flask,
        "MAL-2024-0001": {"id": "MAL-2024-0001", "affected": []},
        "PYSEC-2099-1": {"id": "PYSEC-2099-1", "withdrawn": "2099-01-01T00:00:00Z", "affected": []},
        "PYSEC-2099-2": {
            "id": "PYSEC-2099-2",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "gitonly"},
                    "ranges": [{"type": "GIT", "events": [{"introduced": "abc"}]}],
                }
            ],
        },
    }


def test_osv_full_import_and_rerun(osv_run, upstream: FakeUpstream, db: Session) -> None:  # type: ignore[no-untyped-def]
    payload = osv_zip(osv_records())
    upstream.routes[f"{OSV_BASE}/PyPI/all.zip"] = lambda r: httpx.Response(200, content=payload)

    first = osv_run({"ecosystem": "PyPI"})
    second = osv_run({"ecosystem": "PyPI", "mode": "full"})

    assert (first.status, first.records_inserted, first.records_failed) == ("succeeded", 1, 0)
    assert first.details["skipped_malware_reports"] == 1
    assert first.details["skipped"] == 2  # withdrawn + GIT-only
    assert second.records_unchanged == 1
    advisory = db.get(Advisory, "GHSA-m2qf-hxjv-5gpq")
    assert advisory is not None and advisory.cve_ids == ["CVE-2023-30861"]
    source = db.scalar(select(Source).where(Source.code == "osv"))
    assert source is not None and "PyPI" in (source.watermark or {})


def test_osv_incremental_fetches_changed_records(
    osv_run, upstream: FakeUpstream, db: Session
) -> None:  # type: ignore[no-untyped-def]
    upstream.routes[f"{OSV_BASE}/PyPI/all.zip"] = lambda r: httpx.Response(200, content=osv_zip({}))
    osv_run({"ecosystem": "PyPI"})  # establishes the watermark
    flask = fixture("osv_GHSA-m2qf-hxjv-5gpq.json")
    csv = (
        f"2999-01-01T00:00:00Z,{flask['id']}\n"
        "2999-01-01T00:00:00Z,MAL-2024-9\n"
        "2000-01-01T00:00:00Z,OLD-1\n"
    )
    upstream.routes[f"{OSV_BASE}/PyPI/modified_id.csv"] = lambda r: httpx.Response(200, text=csv)
    upstream.set_json(f"{OSV_BASE}/PyPI/{flask['id']}.json", flask)

    job = osv_run({"ecosystem": "PyPI"})

    assert job.details["mode"] == "incremental" and job.details["changed"] == 1
    assert job.records_inserted == 1
    assert db.get(Advisory, flask["id"]) is not None


def test_osv_incremental_refuses_too_many_changes(osv_run, upstream: FakeUpstream) -> None:  # type: ignore[no-untyped-def]
    upstream.routes[f"{OSV_BASE}/PyPI/all.zip"] = lambda r: httpx.Response(200, content=osv_zip({}))
    osv_run({"ecosystem": "PyPI"})
    csv = "".join(f"2999-01-01T00:00:00Z,GHSA-{i:04d}\n" for i in range(5))
    upstream.routes[f"{OSV_BASE}/PyPI/modified_id.csv"] = lambda r: httpx.Response(200, text=csv)

    job = osv_run({"ecosystem": "PyPI", "max_records": 2})

    assert job.status == "failed" and "run mode=full" in (job.error_summary or "")


def test_osv_rejects_invalid_zip_members(osv_run, upstream: FakeUpstream) -> None:  # type: ignore[no-untyped-def]
    payload = osv_zip({}, extra={"GHSA-bad.json": b"{not json", "nested/GHSA-x.json": b"{}"})
    upstream.routes[f"{OSV_BASE}/PyPI/all.zip"] = lambda r: httpx.Response(200, content=payload)

    job = osv_run({"ecosystem": "PyPI"})

    assert job.status == "failed" and job.records_failed == 1  # nested path ignored


def test_osv_rejects_unknown_ecosystem() -> None:
    with pytest.raises(ParamError):
        OsvAdapter().validate_params({"ecosystem": "Hackage"})
