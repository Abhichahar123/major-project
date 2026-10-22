# Deployment and operations

## Requirements

| Component | Minimum | Notes |
|---|---|---|
| Python | 3.11 (tested on 3.13) | Backend and CLI |
| PostgreSQL | 16 with pgvector ≥ 0.6 | Tested with 0.6.0 (Ubuntu package) and 0.8.0 (`pgvector/pgvector:0.8.0-pg16` image) |
| Docker + Compose plugin | Recent version | Optional, recommended |
| Flutter | 3.47 / Dart 3.13 | Only to build the frontend |
| Ollama | Recent version | Optional: local LLM and semantic embeddings |
| Disk | About 150 MB for the database, plus model sizes | Measured: 147 MB for the demo seed with both OSV exports and the hashing index. During a run, the OSV npm export needs about 220 MB of temporary space |
| RAM | 2 GB for the API and database; see models below | |

Model sizes are approximate, so check `ollama list` after pulling:
- `nomic-embed-text` (embeddings, 768 dimensions) is about 270 MB.
- `llama3.1:8b` (4-bit quantised, the Ollama default) is about 4.7 GB on disk. It needs
  roughly 6–8 GB of free RAM or VRAM to run, and answers in seconds on a GPU and much
  more slowly on a CPU.

These models are **not** downloaded automatically. Pull them explicitly; without them the
app still runs (keyword retrieval with the built-in hashing embedder and evidence-only
answers).

## Option A: Docker Compose

```bash
cp .env.example .env
# Edit .env: set POSTGRES_PASSWORD, ADMIN_API_KEY, and DATABASE_URL (for host CLI use)
docker compose up -d --build                 # db -> migrate (alembic upgrade head) -> api
docker compose ps                            # migrate should show "Exited (0)"
curl http://localhost:8000/health/ready
```

Load the demo dataset. The containers need outbound HTTPS to the source hosts. If your
network blocks that, run the CLI on the host instead (option B, step 3).

```bash
docker compose exec api python -m app.ingestion seed      # about 3 minutes
docker compose exec api python -m app.ingestion jobs
```

Local LLM and semantic embeddings:

```bash
docker compose --profile llm up -d ollama
docker compose exec ollama ollama pull llama3.1:8b
docker compose exec ollama ollama pull nomic-embed-text
# In .env: EMBEDDING_PROVIDER=ollama, then recreate the API and re-embed:
docker compose up -d api
docker compose exec api python -m app.ingestion sync embeddings
```

Google Gemini instead of (or alongside) Ollama, with a free-tier API key:

```bash
# In .env: GEMINI_API_KEY=..., LLM_PROVIDER=gemini, GEMINI_MODEL=<code>
# (optional: EMBEDDING_PROVIDER=gemini, GEMINI_EMBEDDING_MODEL=<code>)
docker compose exec api python -m app.llm.gemini_models   # codes the key can use
docker compose up -d api
docker compose exec api python -m app.ingestion sync embeddings   # only if embeddings changed
```

There are no default Gemini model codes; see [gemini.md](gemini.md) for choosing them,
the data that is sent to Google, and the free-tier limits.

Frontend (served by nginx on port 8090):

```bash
(cd frontend/flutter_app && flutter build web --release --no-web-resources-cdn \
     --dart-define=API_BASE_URL=http://localhost:8000)
docker compose --profile web up -d web        # http://localhost:8090
```

`CORS_ORIGINS` must include the web origin (the default `.env.example` allows
`http://localhost:8090`).

## Option B: run on the host

```bash
# 1. Database (Compose db service, or any PostgreSQL 16 with pgvector)
docker compose up -d db
# 2. Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]" -c constraints.txt
alembic upgrade head                          # needs a role that may CREATE EXTENSION
# 3. Data
python -m app.ingestion seed                  # add --with-npm for the npm OSV export (~220 MB)
# 4. API
uvicorn app.main:app --reload --port 8000
# 5. Frontend
cd ../frontend/flutter_app && flutter run -d chrome --web-port 8090 \
     --dart-define=API_BASE_URL=http://localhost:8000
```

## Database migrations

* `alembic upgrade head`: apply all migrations. Migration `0001` creates the `vector`
  extension and seeds the `sources` table.
* `alembic downgrade -1`: revert the last migration. Downgrading to `base` drops all
  tables but keeps the extension.
* `alembic check`: fail if the models and the migrated schema differ (also covered by
  `tests/integration/test_migrations.py`).
* The API's readiness check reports `migrations: unavailable` when the database revision
  differs from the code's head revision.

## Keeping data fresh

| Task | Command | Suggested schedule |
|---|---|---|
| KEV catalog | `python -m app.ingestion sync kev` | Daily |
| CVE records changed upstream (tracked only) | `python -m app.ingestion sync cve5 --mode delta` | Hourly to daily |
| New KEV CVEs' records | `python -m app.ingestion sync cve5 --mode from_kev --limit 2000` | Daily |
| NVD enrichment (needs network access to NVD; an API key is recommended) | `python -m app.ingestion sync nvd --mode modified` | Daily |
| OSV advisories | `python -m app.ingestion sync osv --ecosystem PyPI` (incremental after the first full run) | Daily |
| ATT&CK, CAPEC | `python -m app.ingestion sync attack` / `sync capec` | Monthly (new releases) |
| Search index | `python -m app.ingestion sync embeddings` | After any of the above |

Use cron, a systemd timer or a CI scheduler. Each command creates an ingestion job. Only
one job per source can run at a time, and a crashed job is marked stale after
`INGESTION_STALE_JOB_MINUTES`.

## Production checklist

* `ENVIRONMENT=production`. Startup then refuses a weak `ADMIN_API_KEY`, `*` or http CORS
  origins, DEBUG logging and the mock LLM. API docs are disabled.
* Put the API behind a TLS-terminating reverse proxy. Rate limits are per process and
  see the proxy's address (see `docs/security.md`).
* Use a dedicated database role for the API after the first migration. Only migrations
  need extension privileges.
* Back up the `pgdata` volume. Everything except the `sources` watermarks can be
  re-ingested.
* Pin the Ollama image tag to a current release (`OLLAMA_IMAGE_TAG`).
* With Gemini: keep `GEMINI_API_KEY` in the server's `.env` or secret store only, and
  restrict the key to the Generative Language API in Google Cloud. A missing key does not
  stop startup in production either: chat degrades to evidence-only and
  `/health/ready` reports `llm: degraded`, so alert on that check.

## Configuration reference

All variables are documented in `.env.example`. The groups are:
- application: name, environment, logging, CORS, body limit;
- the admin key;
- PostgreSQL;
- embeddings: `EMBEDDING_PROVIDER`, `EMBEDDING_MODEL`;
- LLM: `LLM_PROVIDER`, `LLM_MODEL`, `OLLAMA_BASE_URL`, timeouts and token limits, plus
  `LLM_BASE_URL`/`LLM_API_KEY` for an OpenAI-compatible endpoint;
- Gemini: `GEMINI_API_KEY`, `GEMINI_MODEL`, `GEMINI_EMBEDDING_MODEL`,
  `GEMINI_THINKING_BUDGET` ([gemini.md](gemini.md));
- data sources: `NVD_API_KEY`, `OSV_ONLINE_LOOKUP`, feed URLs;
- rate limits.

Settings are validated at startup, and errors name the variable without echoing its
value.
