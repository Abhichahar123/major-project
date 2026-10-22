# API reference

Base path `/api/v1`. Interactive documentation (Swagger UI) is at `/docs`, and the
OpenAPI schema at `/api/v1/openapi.json`. Both are disabled in production.

* **JSON** for every request and response, except the dependency upload (multipart).
* **Errors** use RFC 9457 problem details (`application/problem+json`):
  `{type, title, status, detail, code, request_id}`, with `errors` added for validation
  failures.
* **Every response** carries `X-Request-ID`; quote it when reporting problems.
* **Pagination**: `page` (1–1000) and `page_size` (1–100); responses contain
  `{items, page, page_size, total}`.
* **Rate limits** (per client, per minute, configurable): search/read 120, chat 10,
  dependencies 20, admin 10. Exceeding one returns `429` with `code: rate_limited`.

## Health

| Method | Path | Purpose |
|---|---|---|
| GET | `/health`, `/api/v1/health` | Liveness (no database access) |
| GET | `/api/v1/health/db` | `SELECT 1`; returns 503 when PostgreSQL is unreachable |
| GET | `/health/ready`, `/api/v1/health/ready` | Database, migration revision, pgvector, embeddings, LLM. Returns 503 only for required checks |

```json
{"status": "degraded",
 "checks": {"database": {"status": "ok"},
            "migrations": {"status": "ok", "detail": "0003_osv_advisories"},
            "pgvector": {"status": "ok", "detail": "0.8.0"},
            "embeddings": {"status": "ok", "detail": "hashing/hashing-v2: 3202 chunks (lexical, not semantic)"},
            "llm": {"status": "degraded", "detail": "Ollama not reachable"}}}
```

## Vulnerabilities

### `GET /vulnerabilities`

Search with filters.

| Parameter | Type | Notes |
|---|---|---|
| `q` | string, up to 200 characters | CVE ID (exact match), CVE prefix (`CVE-2024-3`), or free text (`websearch_to_tsquery`: quotes, `OR`, `-term`) |
| `severity` | repeatable: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE` | Display severity |
| `min_cvss`, `max_cvss` | 0–10 | |
| `cwe` | `CWE-79` | |
| `vendor`, `product` | text, up to 100 characters | Case-insensitive substring of affected products |
| `in_kev` | bool | |
| `published_from`, `published_to` | date | |
| `include_rejected` | bool | Default false |
| `sort` | `relevance` / `published` / `cvss` | |

```bash
curl "http://localhost:8000/api/v1/vulnerabilities?q=log4j&severity=CRITICAL&in_kev=true"
```

```json
{"items": [{"cve_id": "CVE-2021-44228", "state": "PUBLISHED",
            "title": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP …",
            "description_snippet": "Apache Log4j2 2.0-beta9 through 2.15.0 …",
            "severity": "CRITICAL", "cvss_base_score": 10.0, "cvss_version": "3.1",
            "published_at": "2021-12-10T00:00:00Z", "in_kev": true,
            "kev_date_added": "2021-12-10", "cwes": ["CWE-20", "CWE-400", "CWE-502"],
            "rank": 0.83}],
 "page": 1, "page_size": 20, "total": 2}
```

Errors: `422` for invalid filters, or when `min_cvss` > `max_cvss` or the dates are
reversed; `503` when the database is down.

### `GET /vulnerabilities/{cve_id}`

Returns everything stored about one CVE: every CVSS score with its provider and source,
the display-severity rule, CWEs with the providers that state them, affected products
with raw version entries, references, the KEV entry, OSV advisories (merged per package,
with fixed versions), and provenance (the source, the record URL, when it was fetched
and when it changed).

* `record_available: false` means the CVE is in CISA KEV but its CVE record has not been
  ingested. Only `kev` is populated in that case.
* Errors: `404` (`cve_not_found`) or `422` for a malformed ID.

### `GET /vulnerabilities/{cve_id}/correlations`

KEV status, weaknesses, CAPEC patterns and inferred ATT&CK techniques with every
`(CWE, CAPEC)` path. Also returns OSV aliases, related CVEs (shared product or weakness),
notes, and the rules used. Every link has `rule` and `relationship`
(`authoritative` | `inferred`); techniques also have `confidence` (`low` | `medium`).

## CISA KEV, ATT&CK and CWE

| Method | Path | Notes |
|---|---|---|
| GET | `/kev` | `q`, `vendor`, `ransomware` (`Known`/`Unknown`), `cwe`, `date_added_from`, `date_added_to`; newest first. Items include `has_cve_record` and the display severity |
| GET | `/techniques` | `q` (text or `T1059.001`), `tactic` (e.g. `initial-access`), `platform`, `include_deprecated` |
| GET | `/techniques/{technique_id}` | Technique and its sub-techniques |
| GET | `/techniques/{technique_id}/vulnerabilities` | CVEs reaching the technique through CWE→CAPEC (inferred), with paths; `limit` up to 200 |
| GET | `/cwes/{cwe_id}` | Vulnerability and KEV counts, CAPEC patterns, reachable techniques |
| GET | `/correlation/rules` | All correlation rules with their kind and limitations |

## Semantic and hybrid search

### `GET /search`

| Parameter | Notes |
|---|---|
| `q` | 2–500 characters |
| `mode` | `hybrid` (default), `semantic`, `keyword` |
| `k` | 1–50 |
| `severity`, `in_kev`, `entity_type` | Filters; `entity_type` is `vulnerability`, `kev` or `attack_technique` |

The response states which mode ran and whether vectors were used, names the embedding
model, says whether it is semantic, and lists any warnings (for example, when it fell
back to keyword search). Results contain one chunk per entity, with snippet, source,
fused score, and keyword and vector ranks.

## Q&A (RAG)

### `POST /chat`

```json
{"question": "Is CVE-2021-44228 exploited in the wild and what should I do?",
 "filters": {"severity": ["CRITICAL"], "in_kev": true, "entity_types": ["vulnerability"]},
 "top_k": 8}
```

* `question`: 3–1,000 characters.
* `filters`: optional.
* `top_k`: optional, 1–20.

```json
{"answer": "Source facts: … [E1] …\n\nAnalysis: …",
 "mode": "generated",
 "grounded": true,
 "citations": [{"id": "E1", "entity_type": "vulnerability", "entity_id": "CVE-2021-44228",
                "cve_id": "CVE-2021-44228", "title": "…", "source_name": "CVE Program record + CISA KEV",
                "source_url": "https://www.cve.org/CVERecord?id=CVE-2021-44228", "snippet": "…"}],
 "cve_ids": ["CVE-2021-44228"],
 "facts": [{"cve_id": "CVE-2021-44228", "severity": "CRITICAL", "cvss_base_score": 10.0,
            "cvss_provider": "CISA-ADP", "in_kev": true, "kev_date_added": "2021-12-10",
            "known_ransomware_use": "Known", "cwes": ["CWE-20", "CWE-400", "CWE-502"], "…": "…"}],
 "warnings": [], "model": {"provider": "ollama", "name": "llama3.1:8b"},
 "retrieval": {"mode": "hybrid", "embedding_model": "…", "semantic": true},
 "prompt_version": "rag-v1", "latency_ms": 2140.3,
 "disclaimer": "Answers are generated from the cited public sources …"}
```

| `mode` | Meaning |
|---|---|
| `generated` | LLM answer, validated against the evidence |
| `evidence_only` | LLM disabled, unreachable or timed out; the retrieved evidence is returned instead |
| `insufficient_evidence` | Nothing relevant was found; the model was not called |
| `refused` | The request asked for exploits, payloads or attack instructions |

`grounded` is true only when the answer cites provided evidence and introduces no CVE IDs
absent from it. `facts` are read from the database, never from the model.

Errors: `422` (validation) and `429` (rate limit). An LLM outage returns
`evidence_only`, not an error.

## Dependency analysis

### `POST /dependencies/analyze`

Multipart upload with field `file`. Accepted files: `requirements*.txt`,
`package-lock.json` or `package.json`, up to 512 KB.

```bash
curl -F "file=@samples/dependencies/requirements-demo.txt" \
     http://localhost:8000/api/v1/dependencies/analyze
```

The response contains `filename`, `sha256`, `format`, `ecosystem`, and the counts
(`dependency_count`, `checked_count`, `unpinned_count`, `vulnerable_packages`). It also
contains:
- `findings[]`, each with `package`, `version`, `specifier`, `confidence`
  (`confirmed`/`uncertain`), `reason`, `advisory_id`, `cve_ids`, `severity`,
  `fixed_versions`, `in_kev`, `source` and `references`;
- `not_checked[]`, `warnings[]`, `summary` and `sources`.

Errors:

| Status | Code | Cause |
|---|---|---|
| 413 | `file_too_large` / `body_too_large` | Over the size limit |
| 415 | `unsupported_manifest` | Unsupported file type |
| 422 | `invalid_manifest`, `empty_file` | File could not be parsed, or is empty |
| 429 | `rate_limited` | Rate limit exceeded |

## Sources and ingestion

| Method | Path | Notes |
|---|---|---|
| GET | `/sources` | Each source with last success, tracked record count and latest job |
| GET | `/ingestion/jobs` | `source`, `status` filters |
| GET | `/ingestion/jobs/{id}` | Status and counts (no per-record errors) |
| GET | `/stats` | Dashboard counts |
| POST | `/admin/ingestion/jobs` | **Admin.** `{"source": "...", "params": {...}}` → `202 {job_id, status, status_url}`; runs in the background |
| GET | `/admin/ingestion/jobs/{id}` | **Admin.** Includes the first 100 per-record errors |

Admin requests need the `X-Admin-Key` header.

| Response | When |
|---|---|
| 401 | Header missing |
| 403 | Wrong key |
| 503 | `ADMIN_API_KEY` not configured |
| 409 | A job for that source is already active |
| 422 | Unknown source or invalid parameters |

Sources and their parameters:

| `source` | Parameters |
|---|---|
| `kev` | none |
| `cve5` | `mode`: `ids` (`ids`: up to 5,000), `from_kev` (`limit`), `tracked`, `delta` (`include_new`, `max_new`, `since_hours`) |
| `nvd` | `mode`: `ids` (up to 200) or `modified` (`modified_since`); `only_tracked` (default true) |
| `attack`, `capec` | none |
| `osv` | `ecosystem` (`PyPI`/`npm`), `mode` (`auto`/`full`/`incremental`), `max_records` |
| `embeddings` | `entity_types`, `reembed`, `prune` (default true) |

```bash
curl -X POST http://localhost:8000/api/v1/admin/ingestion/jobs \
     -H "X-Admin-Key: $ADMIN_API_KEY" -H "Content-Type: application/json" \
     -d '{"source": "cve5", "params": {"mode": "ids", "ids": ["CVE-2023-4966"]}}'
```
