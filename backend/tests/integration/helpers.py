"""Shared helpers for integration tests: a fake upstream serving fixture data."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
KEV_PRIMARY = "https://kev-primary.test/kev.json"
KEV_MIRROR = "https://kev-mirror.test/kev.json"
CVE5 = "https://cve5.test/cves"
NVD = "https://nvd.test/rest/json/cves/2.0"
ATTACK = "https://attack.test/enterprise-attack.json"
CAPEC = "https://capec.test/stix-capec.json"
OSV_BASE = "https://osv.test/osv-vulnerabilities"


def fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text())


class FakeUpstream:
    """Routes requests to fixture payloads; tests can override or break routes."""

    def __init__(self) -> None:
        self.routes: dict[str, Callable[[httpx.Request], httpx.Response]] = {}
        self.calls: list[httpx.Request] = []
        self.set_json(KEV_PRIMARY, fixture("kev_sample.json"))
        for cve in ("CVE-2023-30861", "CVE-2021-44228"):
            year, num = cve.split("-")[1:]
            self.set_json(f"{CVE5}/{year}/{int(num) // 1000}xxx/{cve}.json", fixture(f"{cve}.json"))
        self.set_json(ATTACK, fixture("attack_sample.json"))
        self.set_json(CAPEC, fixture("capec_sample.json"))
        self.set_json(NVD, fixture("nvd_synthetic_page.json"))

    def set_json(self, url: str, payload: Any) -> None:
        self.routes[url] = lambda request: httpx.Response(200, json=payload)

    def set_status(self, url: str, status: int) -> None:
        self.routes[url] = lambda request: httpx.Response(status)

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        url = str(request.url).split("?")[0]
        route = self.routes.get(url)
        return route(request) if route else httpx.Response(404)


def source_settings(database_url: str, **overrides: Any) -> Any:
    """Test settings whose source URLs point at the fake upstream hosts."""
    from tests.conftest import make_settings

    values: dict[str, Any] = {
        "database_url": database_url,
        "kev_feed_urls": [KEV_PRIMARY, KEV_MIRROR],
        "cve5_base_url": CVE5,
        "nvd_api_url": NVD,
        "attack_stix_url": ATTACK,
        "capec_stix_url": CAPEC,
        "osv_data_base_url": OSV_BASE,
        "ingestion_max_retries": 0,
        "ingestion_backoff_base_seconds": 0,
    }
    values.update(overrides)
    return make_settings(**values)


def http_factory_for(settings: Any, upstream: FakeUpstream) -> Callable[[], Any]:
    from app.ingestion.http import SourceHttpClient

    def factory() -> SourceHttpClient:
        return SourceHttpClient(
            allowed_hosts=settings.ingestion_allowed_hosts,
            transport=httpx.MockTransport(upstream.handler),
            max_retries=0,
            sleep=lambda s: None,
        )

    return factory


def seed_fixture_data(settings: Any, session_factory: Any, upstream: FakeUpstream) -> None:
    """Load KEV, ATT&CK, CAPEC, the two CVE fixtures and the flask OSV advisory."""
    import io
    import zipfile

    from app.ingestion.jobs import run_now
    from app.ingestion.sources import (
        AttackAdapter,
        CapecAdapter,
        Cve5Adapter,
        KevAdapter,
        OsvAdapter,
    )

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        flask = fixture("osv_GHSA-m2qf-hxjv-5gpq.json")
        archive.writestr(f"{flask['id']}.json", json.dumps(flask))
    payload = buffer.getvalue()
    upstream.routes[f"{OSV_BASE}/PyPI/all.zip"] = lambda r: httpx.Response(200, content=payload)

    factory = http_factory_for(settings, upstream)
    for adapter, params in (
        (KevAdapter(), {}),
        (AttackAdapter(), {}),
        (CapecAdapter(), {}),
        (Cve5Adapter(), {"mode": "ids", "ids": ["CVE-2023-30861", "CVE-2021-44228"]}),
        (OsvAdapter(), {"ecosystem": "PyPI"}),
    ):
        job = run_now(adapter, params, settings, session_factory, factory)
        assert job.status == "succeeded", (adapter.code, job.error_summary)
