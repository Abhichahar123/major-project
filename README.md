# Indigenous Large Language Models for Cybersecurity Vulnerability Discovery and Threat Intelligence

A final-year B.Tech project. The platform collects public, authoritative security data,
stores it with full provenance, and helps an analyst to:

* **search** CVEs by keyword, product, CWE, severity and exploitation status;
* **understand** a CVE: every CVSS score with its provider, CWEs, affected versions, CISA
  KEV status, package advisories with fixed versions;
* **correlate** CVEs with CWE, CAPEC and MITRE ATT&CK through documented rules that label
  each link *authoritative* or *inferred*;
* **ask questions** answered by a locally hosted open-weight LLM (Ollama) using
  retrieval-augmented generation, with citations, database facts and explicit
  "insufficient evidence" behaviour;
* **check dependencies** (`requirements.txt`, `package-lock.json`, `package.json`)
  against OSV advisories, separating confirmed from uncertain matches.

![Dashboard](docs/images/1-dashboard.png)

| CVE detail | Threat correlation | Grounded Q&A | Dependency analysis |
|---|---|---|---|
| ![](docs/images/3-detail.png) | ![](docs/images/4-correlation.png) | ![](docs/images/6-chat.png) | ![](docs/images/7-dependencies.png) |

## Architecture

```
CISA KEV · CVE Program (CVE JSON 5) · NVD · MITRE ATT&CK · MITRE CAPEC · OSV
        │  allowlisted HTTPS, retries, size caps, per-record validation
        ▼
backend/app/ingestion ──► PostgreSQL 16 + pgvector ◄── backend/app/retrieval (chunks, embeddings, hybrid search)
                               ▲         ▲                          │
            backend/app/correlation   backend/app/dependencies   backend/app/rag + llm (Ollama)
                               └─────────┴──────── FastAPI /api/v1 ─┘
                                                     ▲
                                         frontend/flutter_app (web, Android)
```

See [docs/architecture.md](docs/architecture.md) for components, data model and data flows.

| Area | Where | Docs |
|---|---|---|
| Backend API | `backend/app` (FastAPI, SQLAlchemy 2, Alembic) | [docs/api.md](docs/api.md) |
| Ingestion CLI | `python -m app.ingestion` | [docs/deployment.md](docs/deployment.md) |
| Frontend | `frontend/flutter_app` (Flutter 3.47) | [frontend/flutter_app/README.md](frontend/flutter_app/README.md) |
| Security | | [docs/security.md](docs/security.md) |
| Evaluation | `backend/eval` | [docs/evaluation.md](docs/evaluation.md) |
| Demo and viva | | [docs/demo-guide.md](docs/demo-guide.md) |
| Troubleshooting | | [docs/troubleshooting.md](docs/troubleshooting.md) |
| Progress log | | [docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md) |

## Quick start (Docker Compose)

```bash
cp .env.example .env
# set POSTGRES_PASSWORD, ADMIN_API_KEY (python -c "import secrets;print(secrets.token_urlsafe(32))")
# and DATABASE_URL with the same password (used by the CLI on the host)
docker compose up -d --build                  # db, migrations, API on http://localhost:8000
curl http://localhost:8000/health/ready
```

Load the bounded demo dataset:
- the full KEV catalog;
- 300 recent KEV CVE records and 24 package CVEs;
- ATT&CK, CAPEC and the PyPI OSV export.

```bash
docker compose exec api python -m app.ingestion seed          # about 3 minutes
docker compose exec api python -m app.ingestion seed --with-npm   # optional: also the npm export (~220 MB download)
```

The seed also builds the search index. Optional pieces:

```bash
# Local LLM and semantic embeddings (models are NOT downloaded automatically)
docker compose --profile llm up -d ollama
docker compose exec ollama ollama pull llama3.1:8b        # ~4.7 GB
docker compose exec ollama ollama pull nomic-embed-text   # ~270 MB; then set EMBEDDING_PROVIDER=ollama
docker compose exec api python -m app.ingestion sync embeddings

# Web UI on http://localhost:8090
(cd frontend/flutter_app && flutter build web --release --no-web-resources-cdn \
   --dart-define=API_BASE_URL=http://localhost:8000)
docker compose --profile web up -d web
```

Without Ollama, the platform still works: search uses the built-in lexical embedder, and
chat returns the retrieved evidence (`mode: evidence_only`) instead of a generated answer.

## Development without Docker

```bash
cd backend
python -m venv .venv && source .venv/bin/activate        # Python 3.11+
pip install -e ".[dev]" -c constraints.txt
alembic upgrade head                                     # PostgreSQL 16 with pgvector required
python -m app.ingestion seed
uvicorn app.main:app --reload
```

Common ingestion commands:

```bash
python -m app.ingestion sync kev
python -m app.ingestion sync cve5 --mode ids --ids CVE-2021-44228 CVE-2023-4966
python -m app.ingestion sync cve5 --mode delta           # refresh changed records
python -m app.ingestion sync osv --ecosystem npm
python -m app.ingestion sync embeddings
python -m app.ingestion jobs
```

## Tests and quality checks

```bash
cd backend
ruff check . && ruff format --check . && mypy
pytest                                   # unit tests; integration tests are skipped
TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost:5432/cti_test pytest   # everything
python -m eval.run_eval                  # retrieval / RAG pipeline / dependency evaluation

cd ../frontend/flutter_app
flutter analyze && flutter test
```

Integration tests need a **disposable** database whose name contains `test`: they drop and
recreate the schema. CI (`.github/workflows/ci.yml`) runs everything against
`pgvector/pgvector:0.8.0-pg16`.

Latest local results: 272 backend tests passed (against pgvector 0.6.0 and 0.8.0), and 14
Flutter tests passed. Measured evaluation results are in
[docs/evaluation.md](docs/evaluation.md).

## Data sources and licences

| Source | Content | Terms |
|---|---|---|
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (and the official `cisagov/kev-data` mirror) | Known exploited vulnerabilities | U.S. Government work |
| [CVE Program](https://github.com/CVEProject/cvelistV5) | CVE records (CNA and CISA-ADP containers) | [CVE Terms of Use](https://www.cve.org/Legal/TermsOfUse) |
| [NVD API 2.0](https://nvd.nist.gov/developers) | CVSS/CWE/CPE enrichment (optional) | NVD terms; an API key is recommended |
| [MITRE ATT&CK](https://attack.mitre.org/) and [CAPEC](https://capec.mitre.org/) | Techniques, attack patterns, mappings | MITRE terms of use |
| [OSV](https://osv.dev/) | Package advisories (PyPI, npm) | CC-BY 4.0 (per source) |

The platform is for **defensive analysis** of public data and of manifests you are
authorised to inspect. It does not execute uploaded files, run exploits or scan systems.

## Known limitations

* No real LLM or semantic embedding model could run in the development sandbox. They are
  integrated and tested with mocked HTTP, and the evaluation used the lexical hashing
  embedder and a mock LLM ([details](docs/evaluation.md)).
* NVD ingestion is implemented but was only exercised with synthetic fixtures (the NVD
  API was unreachable from the sandbox). The OSV.dev online lookup is likewise
  mock-tested and off by default.
* The Android build was not run (no Android SDK in the sandbox); the web build was built
  and exercised in a browser.
* Rate limits are per process; there are no user accounts (public read API with an admin
  key).
* Dependency analysis covers PyPI and npm only.
