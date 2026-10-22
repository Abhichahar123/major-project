# Security model

The platform analyses **public** vulnerability data and **user-supplied dependency
manifests**. It never executes uploaded content, never runs exploit code, and never
scans or contacts systems other than its configured data sources and model server.

## Assets and trust boundaries

| Asset | Threat | Boundary |
|---|---|---|
| Admin operations (ingestion jobs) | Unauthorised triggering, resource abuse | `X-Admin-Key` header |
| Database credentials, admin key, LLM API key | Disclosure through logs, errors or responses | Environment variables only |
| Database integrity | SQL injection, malformed upstream data | ORM with bound parameters; validation |
| Server and network | SSRF through ingestion, oversized uploads, ReDoS, decompression bombs | Host allowlist, size caps, bounded parsers |
| Answer integrity | Prompt injection from retrieved documents or questions; fabricated facts | Guardrails and output validation |
| Users of the UI | Malicious links in source data, XSS | Text-only rendering, http(s)-only links, CSP |

## Controls and where they are tested

| Requirement | Control | Code | Tests |
|---|---|---|---|
| Admin authentication | Constant-time comparison of `X-Admin-Key`. 401 when missing, 403 when wrong. Admin endpoints return 503 unless a key of at least 32 characters is configured. Production refuses to start without one | `app/core/security.py`, `app/core/config.py` | `test_api.py::test_admin_*`, `test_config.py::test_production_*` |
| Secret handling | `SecretStr` settings. Log redaction of URL passwords, `Authorization`, `X-Admin-Key`, `*token*`, `*password*`, `*api_key*`. Headers, query strings and bodies are never logged. Chat questions are logged as a hash. Hosted-LLM errors never echo the response body | `app/core/logging.py`, `app/rag/pipeline.py`, `app/llm/providers.py` | `test_logging.py`, `test_errors.py`, `test_rag_unit.py::test_openai_compatible_provider_never_echoes_error_bodies` |
| Input validation | Pydantic schemas with bounded lengths. Strict CVE, CWE and technique ID patterns. Page size at most 100, `q` at most 200 characters, questions at most 1,000 characters. Ingestion parameters are allowlisted per adapter (unknown keys and URLs are rejected) | `app/api/deps.py`, route modules, `app/ingestion/sources.py` | `test_api.py::test_search_validation`, `test_admin_rejects_bad_params_and_unknown_sources` |
| SQL injection | All queries are SQLAlchemy expressions with bound parameters. `LIKE` input is escaped. tsquery lexemes are quoted | `app/services/catalog.py`, `app/retrieval/search.py` | `test_api.py::test_search_text_with_sql_metacharacters_is_safe` |
| SSRF and unsafe fetching | Ingestion contacts only the hosts of the configured https source URLs. Redirects are not followed. Reference URLs found inside records are stored and never fetched. The OSV online lookup uses a fixed URL and is off by default | `app/ingestion/http.py` | `test_ingestion_http.py::test_only_allowlisted_https_hosts`, `test_redirects_are_not_followed` |
| Upstream data safety | Response-size caps. JSON-only parsing. Control and NUL characters are stripped. Only http(s) reference URLs are kept. Zip exports are checked for member size, total size and nested paths | `app/ingestion/normalize.py`, `app/ingestion/sources.py` (`OsvAdapter`) | `test_ingestion_normalize.py`, `test_ingestion.py::test_osv_rejects_invalid_zip_members` |
| Upload restrictions | Filename allowlist, 512 KB limit, UTF-8 only, binary content rejected, at most 5,000 dependencies. Files are parsed as text or JSON; includes, URLs and VCS references are never followed; nothing is installed or run. Uploads are not stored | `app/dependencies/parsers.py`, `app/api/routes/dependencies.py` | `test_dependencies_unit.py::test_unsafe_content_is_rejected`, `test_dependencies.py::test_upload_errors` |
| Request size | Global body limit of 1 MB, enforced by `Content-Length` and by counting streamed bytes | `app/core/middleware.py` | `test_middleware.py::test_body_limit_*` |
| Rate limiting | Per-client sliding windows per minute: search 120, chat 10, dependencies 20, admin 10. In-process only (see limitations) | `app/core/rate_limit.py` | `test_rate_limit.py`, `test_api.py::test_rate_limit`, `test_rag.py::test_chat_rate_limit` |
| Timeouts | Database connect and statement timeouts. Upstream HTTP, embedding and LLM timeouts. Retries are bounded | `app/db/session.py`, `app/ingestion/http.py`, `app/llm/providers.py` | `test_ingestion_http.py`, `test_rag_unit.py::test_ollama_failures` |
| Error leakage | RFC 9457 problem details. Generic 500 with request ID. Database outages return 503 without driver details. Validation errors never echo input | `app/core/exceptions.py` | `test_errors.py`, `test_rate_limit.py::test_data_endpoint_returns_503_when_database_is_down` |
| CORS | Explicit allowlist with no credentials. `*` and http origins are rejected in production | `app/core/config.py`, `app/main.py` | `test_cors.py`, `test_config.py` |
| Response headers | `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and a strict CSP on API responses. Docs are disabled in production | `app/core/middleware.py` | `test_middleware.py` |
| Prompt injection | Questions and evidence are treated as untrusted: evidence is wrapped in delimited blocks, angle brackets are neutralised so tags cannot be closed, and the system rules forbid following embedded instructions. The model has no tools. Injection-like text is flagged | `app/rag/guardrails.py`, `app/rag/prompt.py` | `test_rag_unit.py::test_prompt_wraps_and_neutralizes_evidence`, `test_rag.py::test_injected_evidence_is_neutralized_and_flagged` |
| Unsupported LLM claims | Citations must reference provided evidence (others are removed). CVE IDs absent from the evidence make the answer `grounded=false` with a warning. Facts (CVSS, KEV, CWE) come from the database. If nothing relevant is found, the model is not called | `app/rag/pipeline.py` | `test_rag.py::test_invalid_citations_are_removed`, `test_unsupported_cve_ids_make_answer_ungrounded`, `test_no_relevant_evidence_skips_the_model` |
| Offensive use | Requests for exploits, payloads or attack instructions are refused before retrieval | `app/rag/guardrails.py` | `test_rag_unit.py::test_offensive_requests_are_detected`, `test_rag.py::test_offensive_request_is_refused` |
| Inferred vs authoritative | Every correlation names its rule. Inferred links are labelled and never stored as facts | `app/correlation` | `test_correlation.py` |
| Frontend | Data is rendered as text (no HTML). Only http(s) links are opened. No secrets are built in. The web build can be served without third-party CDNs (`--no-web-resources-cdn`) | `frontend/flutter_app/lib/src/widgets/common.dart` | `flutter test` |
| Container | Non-root user (uid 10001). Ports bound to 127.0.0.1 in Compose | `backend/Dockerfile`, `compose.yaml` | Verified in Phase 2 |
| Dependencies | Exact versions in `constraints.txt`, audited with `pip-audit` | `backend/constraints.txt` | See `docs/IMPLEMENTATION_STATUS.md` |

## Known limitations and residual risk

* **Rate limits are per process.** Running several API workers multiplies the effective
  limit. A shared store (e.g. Redis) would be needed for a multi-worker deployment.
* **The client address is the socket peer.** Behind a reverse proxy every request
  appears to come from the proxy. Configure the proxy's own rate limiting, or add trusted
  proxy handling, before deploying behind one.
* **Prompt injection is mitigated, not solved.** A model can still be influenced by
  adversarial evidence. Users must read the cited sources; the UI shows citations, the
  grounding flag and a disclaimer on every answer.
* **The offensive-request filter is pattern-based** and can be evaded by rephrasing. The
  system prompt also forbids attack instructions, and answers come only from public
  advisory text.
* **No user accounts.** Read endpoints are public by design (public data). Put the API
  behind authentication if deployed on an untrusted network.
* **Dependency matching depends on data coverage.** "No findings" means no known match in
  the ingested OSV/CVE data, not that a package is safe.
