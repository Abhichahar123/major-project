# Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `ConfigurationError: … DATABASE_URL: Field required` at startup | No `.env` or variable | `cp .env.example .env` and set `DATABASE_URL` (on the host) / `POSTGRES_PASSWORD` (Compose) |
| `docker compose up` stops with `required variable POSTGRES_PASSWORD is missing` | `.env` not filled in | Set `POSTGRES_PASSWORD` in `.env` |
| `/health/ready` shows `migrations: unavailable` | Database revision behind the code | `alembic upgrade head` (Compose: `docker compose run --rm migrate`) |
| `alembic upgrade` fails with `permission denied to create extension "vector"` | The role cannot create extensions | Run the first migration as a superuser, or `CREATE EXTENSION vector;` as an admin first |
| `pgvector: unavailable` | pgvector not installed on the server | Use the `pgvector/pgvector` image or install the `postgresql-16-pgvector` package |
| Search returns 503 `database_unavailable` | PostgreSQL down or unreachable | `docker compose ps`; check `DATABASE_URL` host and port |
| KEV job logs "KEV feed unavailable, trying next" | `cisa.gov` blocked or down | Expected: the official CISA GitHub mirror is tried next. If both fail, the job is `failed` and existing data remains |
| NVD job fails with HTTP 403/429 | Rate limit without an API key | Set `NVD_API_KEY`, or use `cve5` records (NVD is optional enrichment) |
| `osv` incremental job fails with "run mode=full instead" | Too many changes since the last run | `python -m app.ingestion sync osv --ecosystem PyPI --mode full` |
| `/search` warns "No embeddings stored" | Embeddings job not run for the current model | `python -m app.ingestion sync embeddings` |
| `/search` warns about a lexical embedder | `EMBEDDING_PROVIDER=hashing` | Expected for development; use Ollama `nomic-embed-text` for semantic search |
| Embeddings job fails with "returns N dimensions; the database stores 768" | Embedding model with another dimension | Use a 768-dimension model, or add a migration changing `vector(768)` and re-embed |
| Chat always returns `evidence_only` | Ollama not running or model not pulled | `ollama serve`; `ollama pull llama3.1:8b`; check `OLLAMA_BASE_URL` (Compose: `http://ollama:11434`) |
| Chat returns `evidence_only` with a Gemini warning | `GEMINI_API_KEY`/`GEMINI_MODEL` not set, invalid key, unknown model, rate limit or daily quota | Read the warning; run `python -m app.llm.gemini_models`; wait for the quota to reset or use a paid key ([gemini.md](gemini.md)) |
| Embeddings job `failed` with "Gemini rate limit" or "daily quota" | Free-tier embedding quota | Re-run later: finished batches are kept and old vectors are not pruned until the run completes |
| Chat is slow or times out | Large model on CPU | Use a smaller model (e.g. `LLM_MODEL=llama3.2:3b`), a GPU, or raise `LLM_TIMEOUT_SECONDS` |
| Chat answers "insufficient evidence" for a real topic | The topic is not in the ingested data, or the wording differs (nicknames such as "Spring4Shell") | Name the CVE ID or product; ingest the record (`sync cve5 --mode ids --ids …`) |
| Flutter web shows a blank page | CanvasKit could not load from Google's CDN | Build with `--no-web-resources-cdn` |
| Flutter shows "Backend not reachable" | Wrong API URL or CORS | Check the URL shown in the app bar; add the web origin to `CORS_ORIGINS` |
| Android emulator cannot reach the API | `localhost` is the emulator itself | The default is `http://10.0.2.2:8000`. For a physical device, use `--dart-define=API_BASE_URL=http://<LAN-IP>:8000` |
| Admin request returns 503 `admin_disabled` | `ADMIN_API_KEY` empty or shorter than 32 characters | Generate one: `python -c "import secrets;print(secrets.token_urlsafe(32))"` |
| 409 `job_conflict` | A job for that source is still running | Wait, or check `/api/v1/ingestion/jobs`. Stale jobs are failed automatically after `INGESTION_STALE_JOB_MINUTES` |
| Integration tests are skipped | `TEST_DATABASE_URL` not set | Point it at a dedicated database whose name contains "test" |
| `docker build` fails with `CERTIFICATE_VERIFY_FAILED` | A TLS-intercepting proxy on your network | Add the proxy's CA to the build (pip `PIP_CERT`), or build on an unrestricted network |
