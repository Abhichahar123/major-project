# Implementation status

Branch `feat/full-platform`, started from `main` at `8a27316` (Phase 2). Updated at every
milestone. Every item marked complete was verified as described in the log below.

## Phase status

| Phase | Status | Summary |
|---|---|---|
| 1. Audit and architecture | complete | `docs/architecture.md` |
| 2. FastAPI foundation | complete | On `main` (`8a27316`); retained and extended |
| 3. Database models and migrations | complete | 20 tables, migrations `0001`–`0003`; round trip and model/schema drift tested |
| 4. Data ingestion | complete | KEV (official feed + CISA GitHub mirror), CVE 5 (ids / from_kev / tracked / delta), NVD (mock-tested only), ATT&CK, CAPEC, OSV PyPI/npm; idempotent, per-record errors, watermarks |
| 5. Vulnerability APIs and search | complete | Search, filters, pagination, detail with provenance, KEV, techniques, sources, jobs, stats, readiness, admin jobs, rate limits |
| 6. Embeddings and semantic retrieval | complete | Chunking, hashing (lexical) and Ollama (semantic, mock-tested) embedders, IDF keyword ranking, exact/HNSW vectors, weighted RRF |
| 7. LLM and RAG | complete | Ollama / OpenAI-compatible / mock / none; guarded prompt; citation and CVE-ID validation; database facts; evidence-only fallback; refusals |
| 8. Threat-intelligence correlation | complete | 8 documented rules, CVE→CWE→CAPEC→ATT&CK paths with confidence, related CVEs |
| 9. Dependency analysis | complete | requirements.txt, package-lock.json (v1–v3), package.json; OSV range evaluation; confirmed vs uncertain |
| 10. Flutter frontend | complete | Dashboard, search, KEV, CVE detail and correlation, Q&A, dependency analysis |
| 11. Security, testing, evaluation | complete | `docs/security.md`, security headers, body limit, pip-audit, `docs/evaluation.md` with measured results |
| 12. Deployment and documentation | complete | Compose (db, migrate, api, optional ollama/web), CI workflow, README, API, deployment, troubleshooting and demo guides |

## Verification summary (latest)

| Check | Result |
|---|---|
| Backend: `ruff check`, `ruff format --check`, `mypy --strict` | Clean |
| Backend tests (unit + integration) vs PostgreSQL 16 + pgvector 0.6.0 | 272 passed |
| Same suite vs the Compose image `pgvector/pgvector:0.8.0-pg16` | 272 passed |
| Flutter `analyze` / `test` / `build web --no-web-resources-cdn` | No issues / 14 passed / built |
| Browser run of the web build against the live API (1280 px and 390 px) | Dashboard, search, detail, correlation, chat (mock LLM), dependencies rendered with real data; no console errors |
| Docker Compose: build, `migrate` (exit 0), API healthy, host seed into the Compose DB, API checks | Passed (sandbox build needed the proxy CA, see below) |
| `pip-audit` of `backend/constraints.txt` | No known vulnerabilities |
| Evaluation (`backend/eval/run_eval.py`) | See `docs/evaluation.md` |
| GitHub Actions CI (run 39836335918 on `56eb43e`) | Passed: backend (ruff, format, mypy, pytest vs pgvector 0.8.0) and frontend (format, analyze, test, web build) |

## What was not verified, and why

* **Real LLM generation and semantic embeddings.** Ollama and Hugging Face downloads are
  blocked in the sandbox and there is no GPU. Both clients are tested with mocked HTTP;
  chat was exercised with the mock provider and with Ollama unreachable (evidence-only
  fallback).
* **NVD and the OSV.dev online API.** Both are unreachable from the sandbox and tested
  with mocks; the NVD fixture is synthetic and labelled as such.
* **Android build.** No Android SDK in the sandbox. The web build was verified.
* **Docker image build without the sandbox workaround.** The sandbox's TLS-intercepting
  proxy required a scratch Dockerfile variant that adds the proxy CA. The repository's
  Dockerfile is unchanged; it has not been built outside the sandbox (CI does not build images).

## Environment facts (development sandbox)

* Reachable: `raw.githubusercontent.com` (CISA `kev-data`, `CVEProject/cvelistV5`,
  `mitre-attack/attack-stix-data`, `mitre/cti`), `storage.googleapis.com` (OSV exports,
  Flutter SDK), PyPI, pub.dev.
* Blocked: `services.nvd.nist.gov`, `www.cisa.gov`, `api.osv.dev`, `huggingface.co`,
  `ollama.com`, `www.gstatic.com`.

## Log

| Milestone | Commit | Pushed | Verification |
|---|---|---|---|
| Phase 2 foundation | `8a27316` | yes (`main`) | 49 tests |
| Architecture and status docs | `e855ee2` | yes | — |
| Phase 3 models and migrations | `c752999` | yes | 54 tests |
| Phase 4a ingestion (KEV, CVE 5, NVD, ATT&CK, CAPEC) | `2e38ac5` | yes | 105 tests; real seed: 1,754 KEV, 615 CAPEC, 867 ATT&CK, 324 CVE records; rerun 100% unchanged |
| Phase 4b OSV advisories | `1879297` | yes | Pushed with one stale migration test failing; fixed in `b1eceb0` (116 tests). Real runs: PyPI 14,012 and npm 7,489 advisories |
| Phase 5 APIs | `49e6f19` | yes | 144 tests; manual run on real data |
| Phase 6 retrieval | `ff9aac0` | yes | 164 tests; 3,311 chunks embedded in about 16 s, rerun unchanged |
| Phase 7 RAG | `0029c17` | yes | 197 tests; manual run with the mock LLM and with Ollama unreachable |
| Phase 8 correlation | `47caf42` | yes | 211 tests |
| Phase 9 dependency analysis | `d06873d` | yes | 267 tests; sample manifests on real OSV data |
| Phase 10 Flutter | `f453628` | yes | analyze clean, 14 tests, web build, browser run |
| Phase 11 security hardening | `14f3260` | yes | 272 tests, pip-audit clean |
| Phase 11 evaluation | `24c85c0` | yes | Pushed while ruff reported 2 E501 errors (gate output was piped); fixed in `f7b5b02` (full gate passing) |
| Phase 12 deployment and docs | see git log | yes | Compose verified end to end; 272 tests vs pgvector 0.8.0; docs |

## Next actions (beyond this implementation)

1. Install Ollama with `llama3.1:8b` and `nomic-embed-text` on the demo machine, set
   `EMBEDDING_PROVIDER=ollama`, re-run `sync embeddings` and `python -m eval.run_eval`,
   and record the semantic and real-LLM results in `docs/evaluation.md`.
2. Run NVD enrichment from a network that can reach `services.nvd.nist.gov` (with an API
   key).
3. Build and test the Android app on a machine with the Android SDK.
4. Open a pull request from `feat/full-platform` to `main` after reviewing the CI run.
