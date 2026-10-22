# Evaluation methodology and results

The numbers below come from actually running `backend/eval/run_eval.py`. The raw output
is in `backend/eval/results/latest.json`, and the generated summary is in
`backend/eval/results/latest.md`. Re-run them after changing data or code.

## What was evaluated

| Area | Labelled set | Metric | Notes |
|---|---|---|---|
| Retrieval | `golden_retrieval.json`: 30 queries | Recall@1/5/10, MRR@10 | One expected record per query |
| RAG pipeline | `golden_rag.json`: 10 answerable, 8 unanswerable, 5 offensive questions | Share of answers citing the expected record, grounded share, citation validity, insufficient-evidence share, refusal share | Uses the **mock** LLM |
| Dependency matching | `golden_dependencies.json`: 36 cases (18 affected, 18 first-fixed) | Confusion matrix, precision, recall | Labels from the fixed versions in each advisory |

Each expected ID is the record a correct answer must rely on. These IDs were chosen from
public knowledge of the vulnerabilities and techniques, and written **before** the
system was run. Query wording deliberately differs from record titles where possible.

### Important caveats

* **The embedder was the lexical `hashing-v2`.** It is not a semantic model: a real
  embedding model (Ollama `nomic-embed-text`) could not be downloaded in the development
  sandbox. "Vector" results therefore measure lexical similarity. Semantic retrieval
  quality is **not measured** here. Re-run the evaluation with `EMBEDDING_PROVIDER=ollama`
  to measure it.
* **The RAG evaluation uses the deterministic mock LLM.** It measures the parts the
  platform controls: evidence selection, the relevance gate, citation validation,
  refusals, and insufficient-evidence handling. It does **not** measure answer quality,
  faithfulness or fluency of a real model. No real LLM was run.
* The sets are small (30, 23 and 36 cases), so differences of one case move a metric by
  3 to 4 percentage points.
* The dataset was the bounded demo seed:
  - CISA KEV catalog version 2026.10.21 (1,754 entries);
  - 325 CVE records;
  - ATT&CK Enterprise v20;
  - CAPEC;
  - OSV PyPI and npm exports (21,501 advisories);
  - 2,481 documents in 3,311 chunks.

## Results (run of 2026-10-22, backend 0.1.0)

### Retrieval

| Mode | Recall@1 | Recall@5 | Recall@10 | MRR@10 | Median latency (ms) |
|---|---|---|---|---|---|
| keyword (IDF-ranked full text) | 0.733 | 0.900 | 0.967 | 0.811 | 28.3 |
| vector (hashing-v2, lexical) | 0.600 | 0.733 | 0.800 | 0.660 | 20.4 |
| hybrid (RRF, lexical vectors down-weighted) | 0.767 | 0.900 | 0.967 | 0.828 | 47.5 |

* Hybrid retrieval was best on Recall@1 and MRR. Lexical vectors alone were clearly
  weaker, which supports giving them a reduced weight in fusion.
* The only hybrid miss was "Microsoft Exchange server-side request forgery ProxyLogon"
  (expected CVE-2021-26855). Other Exchange SSRF CVEs ranked higher, and the nickname
  "ProxyLogon" does not appear in the record text.

### RAG pipeline (mock LLM)

| Check | Result |
|---|---|
| Answerable: expected record cited | 0.9 (9/10) |
| Answerable: answer grounded | 0.9 |
| Answerable: all citations point to provided evidence | 1.0 |
| Unanswerable: "insufficient evidence" | 0.875 (7/8) |
| Offensive: refused | 1.0 (5/5) |

Failures, explained:

* **"Explain the Spring4Shell vulnerability in Spring Framework" got "insufficient
  evidence".** The nickname is absent from the CVE record, so the query terms that do
  match cover less than half of the query's IDF weight. The system declined instead of
  guessing. A semantic embedder would likely recover this case.
* **"What is the capital of Australia?" was answered from unrelated ATT&CK text.** With
  only two content terms, the prefix lexeme `capit:*` matched technique descriptions, and
  coverage reached 0.517, just over the 0.5 threshold. This is a known weakness of
  lexical relevance gating on very short questions. The threshold was **not** tuned to
  this test set.

### Dependency matching

| TP | FP | FN | TN | Precision | Recall | Accuracy |
|---|---|---|---|---|---|---|
| 18 | 0 | 0 | 18 | 1.0 | 1.0 | 1.0 |

Every labelled affected version was confirmed, and every first-fixed version was cleared.
This shows the OSV range evaluation is correct on these boundary cases. It does not
measure coverage: packages or advisories missing from the OSV export cannot be found.

## Reproducing

```bash
cd backend
python -m app.ingestion seed --with-npm     # or reuse an existing database
python -m app.ingestion sync embeddings
python -m eval.run_eval                     # prints and writes eval/results/latest.*
```

To evaluate semantic retrieval, install Ollama and run
`ollama pull nomic-embed-text`. Then set `EMBEDDING_PROVIDER=ollama`, run the
embeddings job, and re-run the evaluation. The same works with
`EMBEDDING_PROVIDER=gemini` and `GEMINI_EMBEDDING_MODEL` ([gemini.md](gemini.md)).

To evaluate a real model instead of the mock, configure it (for example
`LLM_PROVIDER=gemini` with `GEMINI_MODEL`) and run:

```bash
python -m eval.run_eval --llm configured --llm-delay 13
```

`--llm-delay` keeps a free-tier key under its per-minute limit (only the 10 answerable
questions reach the model). Check the "answered by the model" row first: answers that
fell back to evidence only (rate limit, quota, outage) are not model answers, and a rate
below 1.0 means the run did not fully measure the model. **No Gemini or other real-model
evaluation has been run yet**; the results above are mock-LLM results.
