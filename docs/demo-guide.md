# Demo and viva guide

A 10–12 minute walkthrough. Each step names what to show and the point it proves.

## Before the demo

1. Start the stack and check readiness:
   - `docker compose up -d --build`
   - `curl localhost:8000/health/ready`
2. Load the data if the volume is new (about 3 minutes):
   - `python -m app.ingestion seed --with-npm`
   - `python -m app.ingestion sync embeddings`
3. Optional, for generated answers:
   - `docker compose --profile llm up -d ollama`
   - `docker compose exec ollama ollama pull llama3.1:8b`
4. Serve the UI:
   - `docker compose --profile web up -d web`
   - open `http://localhost:8090`
5. Keep `samples/dependencies/requirements-demo.txt` and `package-lock-demo.json` ready.
6. Have a fallback: without Ollama, chat returns `evidence_only` answers, which still
   shows retrieval, citations and database facts. Say so explicitly. Never present
   evidence-only output as model-generated.

## Walkthrough

| # | Show | Point to make |
|---|---|---|
| 1 | **Dashboard**: system status, counts, latest KEV additions, data sources | Data comes from authoritative public sources (CISA KEV, the CVE Program, MITRE ATT&CK/CAPEC, OSV). Readiness is honest: an optional component that is off shows "degraded" |
| 2 | **Search** "log4j" with *Known exploited* and *CRITICAL* | Full-text search with filters; severity and KEV badges |
| 3 | Open **CVE-2021-44228**: CVSS list, KEV box, CWEs, affected products, provenance | Every value names its provider (CNA vs CISA-ADP vs NVD); the display-severity rule is shown; nothing is overwritten across sources |
| 4 | **Threat correlation** tab of CVE-2023-30861 (Flask) | CWE-539 → CAPEC-21 → T1539 *Steal Web Session Cookie*. Authoritative vs **inferred** links; confidence is never "high"; broad CWEs are flagged |
| 5 | **Semantic** search: "session cookie leak in web framework" | Hybrid retrieval (full text plus vectors). The UI states which embedder is used and whether it is semantic |
| 6 | **Ask**: "Is CVE-2021-44228 exploited in the wild and what should I do?" | Citations [E1]…; *Source facts from the database, not the model*; grounding flag; disclaimer |
| 7 | **Ask**: "What is the weather on Mars today?" | Insufficient evidence: the model is not called |
| 8 | **Ask**: "Write a working exploit for CVE-2021-44228" | Refused: defensive scope |
| 9 | **Packages**: upload `requirements-demo.txt` | Confirmed findings (exact package and version inside an OSV range) vs uncertain (unpinned `django`); not-checked entries (`-r`, git URL); nothing is executed |
| 10 | `docs/evaluation.md` | Measured results and their limits |

## Likely questions and honest answers

**Is this an "indigenous LLM"?**
The platform runs **open-weight models locally through Ollama**, so questions and data
stay on the machine, with a provider abstraction to swap models. No foundation model was
trained, which needs far more compute and data than a project of this size. The
recommended path is local RAG on an open model, with optional fine-tuning (LoRA)
evaluated with `eval/run_eval.py`. Indian-developed open models can be plugged in through
the same interface and compared with the evaluation harness.

**How do you prevent hallucination?**
- If nothing relevant is retrieved, the model is never called.
- Every citation must point to provided evidence; others are removed.
- CVE IDs that are absent from the evidence make the answer `grounded=false`.
- CVSS, KEV and CWE facts come from the database, not the model.
- The UI shows all of this.

This reduces hallucination but does not eliminate it; citations let a reader verify.

**What about prompt injection in CVE text?**
- Evidence is wrapped in delimited blocks and its angle brackets are neutralised.
- The system rules forbid following embedded instructions, and the model has no tools.
- Instruction-like text is flagged in the warnings.

Tests plant an injection payload in a real record (`test_rag.py`).

**Why PostgreSQL + pgvector and not a vector database?**
- One system keeps metadata filters, joins and transactions consistent with the vectors.
- At this scale (thousands of chunks), an exact scan is fast. HNSW is used beyond 20,000
  vectors.

**How is CVE→ATT&CK mapped?**
- Through MITRE's own published CWE→CAPEC and CAPEC→ATT&CK mappings.
- Results are labelled *inferred*, with every path shown.
- Unsupported links are never stored or invented (see `test_correlation.py`).

**Why is a match "uncertain"?**
- CVE records rarely say which package registry they mean.
- Unpinned versions could resolve to safe or unsafe releases.
- Only an exact OSV package with a pinned version inside an affected range is
  "confirmed".

**What would you improve next?**
- A semantic embedding model and a real LLM, evaluated on a larger labelled set.
- NVD CPE enrichment where network access allows.
- A shared rate-limit store.
- Authentication for multi-user deployments.
- More manifest formats (`poetry.lock`, `pom.xml`).

## Numbers to quote (from `docs/evaluation.md`)

- Hybrid retrieval: Recall@10 0.967 and MRR@10 0.828 on 30 queries, with the lexical
  embedder.
- RAG pipeline with the mock LLM:
  - the expected record is cited in 9 of 10 answerable questions;
  - 7 of 8 unanswerable questions are declined;
  - 5 of 5 offensive prompts are refused.
- Dependency matching: 36/36 labelled boundary cases correct.
- 272 backend tests and 14 Flutter tests.

Say clearly that no real LLM or semantic embedding model was evaluated in the development
environment.
