# Testing strategy

| Layer | Location | Needs | What it covers |
|---|---|---|---|
| Unit (backend) | `backend/tests/test_*.py` | Nothing | Config validation; logging redaction; error responses; CORS; security headers; body limits; rate limiter; HTTP client retries, allowlist and size caps; normalizers (real CVE 5, KEV, ATT&CK, CAPEC and OSV records; synthetic NVD page); chunking; embedders (Ollama mocked); guardrails and prompt construction; LLM providers (mocked); Gemini provider and embedder through the real SDK over a mocked API (`test_gemini.py`); manifest parsers; version-range logic |
| Integration (backend) | `backend/tests/integration/` | `TEST_DATABASE_URL` (PostgreSQL + pgvector, name containing "test") | Migrations (round trip, no drift, constraints); ingestion of every source with mocked upstreams (idempotency, partial failures, outages, watermarks, conflicts); API endpoints; retrieval; RAG pipeline with deterministic and adversarial LLM stubs, and with the Gemini provider over a mocked API (`test_gemini_rag.py`); correlation rules; dependency matching and uploads |
| Frontend | `frontend/flutter_app/test/` | Flutter SDK | API client (query building, problem details, network errors, multipart); widget tests for dashboard, search, chat and dependency screens, including empty and error states |
| Evaluation | `backend/eval/` | Seeded database | Retrieval Recall@k/MRR, RAG pipeline behaviour, dependency-matching confusion matrix (`docs/evaluation.md`) |
| End to end (manual, scripted) | — | Running stack | Compose stack: migrate → API → host seed → API checks. Flutter web build driven in headless Chromium against the live API |

Principles:

* **No live external APIs in tests.** Upstream HTTP uses `httpx.MockTransport` with real
  record fixtures (except one synthetic NVD page, which is labelled as such).
* **Integration tests are destructive by design.** They refuse to run against a database
  whose name lacks "test".
* **No API key is ever required.** Gemini tests run the official SDK against
  `httpx.MockTransport`; the test fixtures remove any `GEMINI_*`/`GOOGLE_API_KEY` from the
  environment so a developer's real key cannot be used.
* **The LLM is never required.** The `mock` provider is deterministic. Adversarial stubs
  return invalid citations, unsupported CVE IDs or nothing, and outages are simulated.
* **Failing tests are fixed, not weakened.** When a test exposed a bug (for example the
  prompt budget off by three characters, a redirect treated as success, or the npm
  package matched to a PyPI CVE), the code was fixed.
