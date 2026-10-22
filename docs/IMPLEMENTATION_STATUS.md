# Implementation status

Branch: `feat/full-platform` (from `main` at `8a27316`). Updated at every milestone.

## Phase status

| Phase | Status | Notes |
|---|---|---|
| 1. Audit and architecture | complete | `docs/architecture.md` |
| 2. FastAPI foundation | complete | Committed on `main` as `8a27316` |
| 3. Database models and migrations | complete | 18 tables, migrations `0001`, `0002`; round trip and drift tested |
| 4. Data ingestion | complete | KEV, CVE 5, NVD (mocked only), ATT&CK, CAPEC, OSV (PyPI, npm) |
| 5. Vulnerability APIs and search | complete | search/filters/pagination, CVE detail with provenance, KEV, techniques, sources, jobs, stats, readiness, admin jobs (X-Admin-Key), rate limits |
| 6. Embeddings and semantic retrieval | pending | |
| 7. LLM and RAG | pending | |
| 8. Threat-intelligence correlation | pending | |
| 9. Dependency analysis | pending | |
| 10. Flutter frontend | pending | |
| 11. Security, testing, evaluation | pending | |
| 12. Deployment and documentation | pending | |

## Environment facts (development sandbox)

These were checked in the sandbox used to build the project, not assumed.

* Reachable: `raw.githubusercontent.com` (CISA `kev-data`, `CVEProject/cvelistV5`,
  `mitre-attack/attack-stix-data`, `mitre/cti`), PyPI, pub.dev and the Flutter SDK download.
* Blocked by the sandbox egress proxy: `services.nvd.nist.gov`, `www.cisa.gov`,
  `api.osv.dev`, `huggingface.co`, `ollama.com`. Code for these is tested with mocked
  HTTP only.
* No GPU, so no real LLM or embedding model can run in the sandbox.

## Log

| Milestone | Commit | Pushed | Tests |
|---|---|---|---|
| Phase 2 foundation | `8a27316` | yes (`main`) | 49 passed (45 unit, 4 integration) |
| Phase 3 models and migrations | `c752999` | yes | 54 passed |
| Phase 4a ingestion | `2e38ac5` | yes | 105 passed |
| Phase 4b OSV advisories | `1879297` (+ fix `b1eceb0`) | yes | 113 passed; real runs: PyPI 14,012 and npm 7,489 advisories imported (11,922 and 222,729 MAL- reports skipped); full rerun 100% unchanged. Note: `1879297` was pushed with one stale test failing; `b1eceb0` fixed it |
| Phase 5 APIs | see git log | yes | 144 passed (unit + integration); manual run against the real seeded database |
