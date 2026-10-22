# Indigenous Large Language Models for Cybersecurity Vulnerability Discovery and Threat Intelligence

A final-year engineering project: an AI-assisted cybersecurity platform that will collect
public vulnerability and threat-intelligence data (CVE/NVD, CISA KEV, MITRE ATT&CK),
store it in PostgreSQL, and answer security questions with a self-hosted open-weight LLM
using retrieval-augmented generation (RAG) with source citations.

## Current status: Phase 2, backend foundation

What exists today:

| Component | Status |
|---|---|
| FastAPI application (app factory, versioned `/api/v1` prefix) | Implemented |
| `GET /health` and `GET /api/v1/health` (liveness) | Implemented |
| `GET /api/v1/health/db` (PostgreSQL connectivity) | Implemented |
| Environment-based configuration with startup validation | Implemented |
| Structured JSON logging with secret redaction and request IDs | Implemented |
| Centralized error handling (RFC 9457 problem details, no stack traces to clients) | Implemented |
| CORS with an explicit origin allowlist | Implemented |
| SQLAlchemy 2.x engine and session management (psycopg 3) | Implemented |
| Docker Compose with PostgreSQL 16 + pgvector | Configured |
| Unit tests and database integration tests | Implemented |

What does **not** exist yet: vulnerability ingestion, the database schema and Alembic
migrations, search APIs, embeddings, the LLM/Ollama integration, RAG chat, dependency
analysis, admin endpoints and the Flutter frontend. See [Roadmap](#roadmap).

## Repository layout

```
.
├── compose.yaml            # PostgreSQL (pgvector) + API for local development
├── .env.example            # configuration template, copy to .env
└── backend/
    ├── pyproject.toml      # dependencies and tool configuration
    ├── constraints.txt     # exact tested dependency versions
    ├── Dockerfile
    ├── app/
    │   ├── main.py         # create_app() and the ASGI `app`
    │   ├── api/routes/health.py
    │   ├── core/           # config.py, logging.py, exceptions.py
    │   └── db/             # session.py (engine/sessions), base.py (ORM base)
    └── tests/              # unit tests; integration/ needs a real PostgreSQL
```

## Prerequisites

- Python 3.11 or newer (developed and tested on Python 3.13)
- Docker with the Compose plugin, for PostgreSQL (or any PostgreSQL 16 with pgvector)
- `git`

## Setup

```bash
git clone https://github.com/Abhichahar123/major-project.git
cd major-project
cp .env.example .env
```

Edit `.env`:

1. Set `POSTGRES_PASSWORD` to a strong value (letters, digits, `-` and `_`).
2. Put the same password into `DATABASE_URL` in place of `REPLACE_WITH_POSTGRES_PASSWORD`.

To generate a password or admin key:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

`.env` is git-ignored. Never commit it.

## Configuration

All settings come from environment variables or `.env`. Real environment variables take
precedence over `.env`. Names are case-insensitive.

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | **required** | `postgresql+psycopg://user:password@host:5432/db` |
| `APP_NAME` | `Cyber Threat Intelligence API` | Shown in health responses and API docs |
| `ENVIRONMENT` | `development` | `development`, `test` or `production` |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| `LOG_FORMAT` | `json` | `json` (one object per line) or `text` |
| `API_V1_PREFIX` | `/api/v1` | Prefix for versioned endpoints |
| `CORS_ORIGINS` | empty (CORS disabled) | Comma-separated allowlist, e.g. `http://localhost:3000` |
| `ADMIN_API_KEY` | empty | Key for admin operations (used from Phase 3). Admin operations stay disabled unless it is at least 32 characters |
| `DB_POOL_SIZE` | `5` | Connection pool size |
| `DB_MAX_OVERFLOW` | `5` | Extra connections allowed above the pool size |
| `DB_CONNECT_TIMEOUT_SECONDS` | `5` | Connection timeout |
| `DB_STATEMENT_TIMEOUT_MS` | `5000` | PostgreSQL `statement_timeout` per connection |
| `POSTGRES_DB` / `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_PORT` | `cti` / `cti` / **required** / `5432` | Used by Docker Compose |
| `API_PORT` | `8000` | Host port for the API container |

Invalid or missing settings stop the application at startup with a message naming each
variable. Values are never printed. For example:

```
app.core.exceptions.ConfigurationError: Invalid application configuration:
  - DATABASE_URL: Field required
Set these environment variables or add them to .env (see .env.example).
```

`ENVIRONMENT=production` adds stricter checks:
- `ADMIN_API_KEY` must be at least 32 characters and not a placeholder.
- `CORS_ORIGINS` may not contain `*` and must use `https://`.
- `LOG_LEVEL` may not be `DEBUG`.
- Interactive docs (`/docs`, OpenAPI JSON) are switched off.

## Start PostgreSQL with Docker Compose

```bash
docker compose up -d db
docker compose ps          # wait until db shows "healthy"
```

The database:
- runs the `pgvector/pgvector:0.8.0-pg16` image
- stores data in the named volume `cti_pgdata`
- listens only on `127.0.0.1:${POSTGRES_PORT}`

Stopping it with `docker compose down` keeps the volume. Adding `-v` deletes your data.

### Enabling pgvector

The image ships the extension, but each database must enable it once. Phase 3 does this in
the first Alembic migration. To enable it by hand:

```bash
# Replace "cti" if you changed POSTGRES_USER or POSTGRES_DB.
docker compose exec db psql -U cti -d cti \
  -c "CREATE EXTENSION IF NOT EXISTS vector;" \
  -c "SELECT extversion FROM pg_extension WHERE extname = 'vector';"
```

## Run the API locally

From the `backend` directory, using a virtual environment:

```bash
cd backend
python -m venv .venv
source .venv/bin/activate              # Windows: .venv\Scripts\activate
pip install -e ".[dev]" -c constraints.txt
uvicorn app.main:app --reload --port 8000
```

The app reads `../.env` (the repository root) when started from `backend/`. Interactive API
docs are at <http://localhost:8000/docs> outside production.

### Or run everything in Docker

```bash
docker compose up -d --build
```

Inside the Compose network the API connects to the host `db`. Compose builds that URL
itself, so the `DATABASE_URL` line in `.env` is only used when running uvicorn on the host.

## Health endpoints

```bash
curl -i http://localhost:8000/health
# HTTP/1.1 200 OK
# x-request-id: 72b05dcc6d7648cc8f5353b2f02ef223
# {"status":"ok","service":"Cyber Threat Intelligence API","version":"0.1.0"}

curl http://localhost:8000/api/v1/health
# {"status":"ok","service":"Cyber Threat Intelligence API","version":"0.1.0"}

curl http://localhost:8000/api/v1/health/db
# 200 {"status":"ok","database":"ok","latency_ms":24.17}
# 503 {"status":"unavailable","database":"unreachable","latency_ms":null}   (database down)
```

Errors use [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) problem details with content
type `application/problem+json`:

```json
{"type":"about:blank","title":"Not Found","status":404,"detail":"Not Found",
 "code":"not_found","request_id":"efc85279213e42fbaad3a3cb90436443"}
```

Every response carries an `X-Request-ID` header. Server logs use the same ID, so quote it
when reporting a problem. Unexpected errors return a generic 500 message. Tracebacks are
logged server-side only, with credentials redacted.

## Tests and code quality

From `backend/` with the virtual environment active:

```bash
pytest                       # unit tests; integration tests are skipped
ruff check . && ruff format --check .
mypy
```

The integration tests need a running PostgreSQL. With the Compose database up:

```bash
TEST_DATABASE_URL="postgresql+psycopg://cti:<password>@localhost:5432/cti" pytest -m integration
```

They check a real `SELECT 1`, the `/api/v1/health/db` endpoint, that `statement_timeout` is
applied, and that pgvector is available on the server. Set `EXPECT_PGVECTOR=0` to skip the
pgvector check on a server without it.

Unit tests never contact a database: they replace the engine with a mock, or point it at
`127.0.0.1:1`, where nothing is listening, to exercise the failure path.

## Known limitations

- No business functionality yet; this phase is infrastructure only.
- Ollama and the LLM/RAG pipeline are **not** implemented or configured.
- The schema and Alembic migrations arrive in Phase 3. `app/db/base.py` only defines the
  declarative base and constraint naming convention.
- `ADMIN_API_KEY` is validated but no endpoint uses it yet.
- No rate limiting yet (planned with the public search and chat endpoints).
- `POSTGRES_PASSWORD` is placed into a URL by Compose, so avoid `@ : / ? #` in it.
- Starlette prints a deprecation warning about `httpx` in its test client. Tests still pass;
  this will be revisited when upgrading dependencies.

## Roadmap

| Phase | Scope |
|---|---|
| 1 | Analysis and architecture (done) |
| 2 | Backend foundation (this phase) |
| 3 | Database schema, Alembic, ingestion of CISA KEV and NVD CVE data, admin-protected ingestion endpoints |
| 4 | MITRE ATT&CK/CAPEC/CWE data and evidence-backed CVE-to-technique correlation |
| 5 | Vulnerability and technique search APIs |
| 6 | Embeddings and hybrid (full-text + pgvector) retrieval |
| 7 | Ollama LLM provider and RAG chat with citations |
| 8 | Dependency manifest vulnerability analysis |
| 9 | Vulnerability classification and prioritisation |
| 10 | Flutter frontend |
| 11 | Hardening, evaluation and deployment |
