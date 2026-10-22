# Google Gemini (optional cloud provider)

The platform's default is local inference through Ollama. Gemini is an **optional** cloud
alternative for chat answers (`LLM_PROVIDER=gemini`) and, separately, for semantic
embeddings (`EMBEDDING_PROVIDER=gemini`). It uses the official Google Gen AI SDK
(`google-genai`, pinned in `backend/constraints.txt`).

Status: implemented and tested against a **mocked** Gemini API only. No real Gemini call
has been made from the development environment, because no API key was available there.
See [What was and was not verified](#what-was-and-was-not-verified).

## Before you enable it

* **Data leaves the machine.** With `LLM_PROVIDER=gemini`, every chat question that
  passes the refusal and relevance checks is sent to Google with up to
  `RAG_MAX_CONTEXT_CHARS` of retrieved evidence. With `EMBEDDING_PROVIDER=gemini`, every
  document chunk (during indexing) and every search query is sent to Google.
  Dependency manifests are never sent.
* **Free-tier terms.** Google's pricing page states that content sent on the free tier
  may be used to improve Google's products. Use the free tier only with public data and
  questions that contain nothing confidential. Check Google's current terms yourself.
* **Free-tier limits are small and change.** Third-party reports for October 2026 range
  from about 20 to 1,500 generation requests per day per model, and about 100 embedding
  requests per minute. The official numbers for your key are on the rate-limit page in
  Google AI Studio. The platform handles the limits (see below), but a small daily quota
  means many chat answers will be evidence-only.

## Choosing model codes

There are **no default model codes**. Google renames, previews and retires Gemini models
often, and free-tier availability differs per model. A hard-coded default would go stale.
Set the codes explicitly:

1. Create an API key in Google AI Studio.
2. Put it in the **backend** `.env` (never in the Flutter app):

   ```bash
   GEMINI_API_KEY=...            # backend .env only
   ```

3. List what the key can use:

   ```bash
   cd backend
   python -m app.llm.gemini_models
   # <model code>                          generation
   # <model code>                          embeddings
   ```

4. Check the free-tier column of the official pricing page
   (<https://ai.google.dev/gemini-api/docs/pricing>) and the deprecations page
   (<https://ai.google.dev/gemini-api/docs/deprecations>) for the codes you picked.
5. Set them:

   ```bash
   LLM_PROVIDER=gemini
   GEMINI_MODEL=<a free-tier generation model from step 3>
   # optional, separately:
   EMBEDDING_PROVIDER=gemini
   GEMINI_EMBEDDING_MODEL=<a free-tier embedding model from step 3>
   ```

When this was written (October 2026), the official pages could not be fetched from the
development sandbox. Web search results pointed to the Gemini 2.5 Flash / Flash-Lite and
3.x Flash / Flash-Lite families as free-tier generation models, and
`gemini-embedding-001` as the free-tier embedding model. These are **not verified** and
are not used as defaults. Confirm them with the steps above.

Model codes are validated (lowercase letters, digits, `.` and `-`, optional `models/`
prefix), so a configuration value cannot change the request path.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `GEMINI_API_KEY` | empty | API key (`SecretStr`; masked in `repr`, redacted from logs) |
| `GEMINI_MODEL` | empty | Generation model code, used when `LLM_PROVIDER=gemini` |
| `GEMINI_EMBEDDING_MODEL` | empty | Embedding model code, used when `EMBEDDING_PROVIDER=gemini` |
| `GEMINI_THINKING_BUDGET` | empty | Thinking-token budget for models that support it. Empty keeps the model default; `0` turns thinking off where the model allows it |
| `LLM_MAX_TOKENS`, `LLM_TEMPERATURE`, `LLM_TIMEOUT_SECONDS` | 700, 0.1, 90 | Shared with the other LLM providers. On thinking models, thinking tokens count against `LLM_MAX_TOKENS` |
| `EMBEDDING_TIMEOUT_SECONDS` | 60 | Per embedding request |

With Docker Compose, the four `GEMINI_*` variables are passed from `.env` to the `api`
service only (not to `migrate`), and are never baked into the image.

## What happens when something is missing or fails

| Situation | Chat (`LLM_PROVIDER=gemini`) | Search / indexing (`EMBEDDING_PROVIDER=gemini`) |
|---|---|---|
| Key or model not set | API starts; answers are `evidence_only` with a warning naming the missing variable; `/health/ready` reports `llm: degraded` | API starts; search is keyword-only; the embeddings job records why and embeds nothing |
| Per-minute rate limit (HTTP 429) | `evidence_only` at once (no waiting). Gemini is then not called until the retry delay Google sent (default 30 s) has passed | Queries: keyword-only at once. Indexing: waits out the delay and retries, at most 3 times and only for delays up to 65 s |
| Daily quota exhausted | `evidence_only`; Gemini is not called for at least 10 minutes | Indexing stops; already embedded batches are kept, and a re-run continues |
| Invalid key (400 `API_KEY_INVALID`, 401, 403) | `evidence_only`, warning "check GEMINI_API_KEY" | Indexing fails with the same message |
| Unknown model (404) | `evidence_only`, warning pointing to `python -m app.llm.gemini_models` | Same |
| Timeout, network error, 5xx, unparseable response | `evidence_only` (`LLMTimeoutError` / `LLMUnavailableError`) | Queries: keyword-only. Indexing: stops without retrying; finished batches are kept |
| Prompt blocked, or answer stopped for `SAFETY`, `RECITATION`, `PROHIBITED_CONTENT` and similar | `evidence_only`; **none** of the stopped text is shown | — |
| Answer cut at `MAX_TOKENS` | Shown with "cut at the length limit"; if empty, `evidence_only` with a hint to raise `LLM_MAX_TOKENS` | — |
| Embedding with the wrong dimension, wrong count, or all zeros | — | Rejected; nothing is stored |

`/health/ready` never calls Gemini (every call counts against the quota). It reports the
configured model as "not probed", or `degraded` while a rate-limit cooldown is active.

Error messages are built from the HTTP status and Google's machine-readable error fields
only. Response bodies are never shown to users or written to logs.

## Safety is unchanged

Gemini only replaces the text generator. Everything around it still runs:

* Offensive requests are refused, and off-topic questions get "insufficient evidence",
  **before** any Gemini call.
* Evidence is sent as delimited, untrusted blocks under the same system rules
  (`app/rag/prompt.py`).
* Citations must point to provided evidence, and CVE IDs missing from the evidence make
  the answer `grounded=false`.
* CVSS, KEV and CWE facts shown with the answer come from the database.
* Google's default safety settings are used; the platform never loosens them. The model
  gets no tools (automatic function calling is disabled).

Tests: `backend/tests/integration/test_gemini_rag.py`.

## Vector dimensions and the database

The `chunk_embeddings.embedding` column is `vector(768)`, fixed by migration `0001`.
Gemini embedding models return more dimensions by default (`gemini-embedding-001`
returns 3,072), so the embedder requests `output_dimensionality=768` and L2-normalises
the result (Google's reduced-dimension embeddings are not unit length).

* **No schema change and no migration.** Changing the column would need a new migration,
  a rebuild of the HNSW index and a re-embed of every chunk, and would break the Ollama
  and hashing embedders, which produce 768 dimensions.
* Gemini vectors are stored as a separate `embedding_models` row (provider `gemini`, the
  model code, 768). They are never compared with another model's vectors.
* A vector that is not exactly 768 values long is rejected rather than truncated or
  padded.
* Switching embedders: run `python -m app.ingestion sync embeddings`. Other models'
  vectors are deleted only after **every** chunk was embedded with the new model. A run
  that stops on a quota error keeps the previous model's vectors, and records
  `prune: skipped`. Re-run it later to finish.
* Switching back to `hashing` or `ollama` requires a re-embed with that model.

With the demo seed (3,311 chunks), indexing sends 104 requests at the default
`EMBEDDING_BATCH_SIZE=32`. Set `EMBEDDING_BATCH_SIZE=100` (the API's maximum per request)
to send 34. Whether Google counts a batch as one request or as one per text against the
quota is not stated on the pages that could be checked.

## Evaluating with Gemini

```bash
cd backend
python -m eval.run_eval --llm configured --llm-delay 13
```

`--llm-delay` pauses between model calls to stay under per-minute free-tier limits. The
report shows "answered by the model": answers that fell back to evidence only
(rate limit, quota or outage) are counted there and say nothing about the model. No
Gemini evaluation has been run yet, so `docs/evaluation.md` contains mock-LLM results
only.

## What was and was not verified

| Item | Status |
|---|---|
| SDK request shape (endpoint, `x-goog-api-key` header, system instruction, generation config, `outputDimensionality`, task types) | Verified: the real SDK runs against `httpx.MockTransport` in `tests/test_gemini.py` |
| Error, quota, timeout, safety-block and empty-answer handling | Verified with mocked responses |
| Guardrails with Gemini as the model | Verified in `tests/integration/test_gemini_rag.py` against PostgreSQL |
| `generativelanguage.googleapis.com` reachable from the sandbox | Yes (it answered 403 `PERMISSION_DENIED` without a key) |
| A real generation or embedding call | **Not done:** no API key was available |
| Current free-tier model codes | **Not verified** against official pages (unreachable from the sandbox). Use the steps above |
| Answer quality with Gemini | **Not measured** |
