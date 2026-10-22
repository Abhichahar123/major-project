# Evaluation results

Generated 2026-10-22T18:49:04+00:00 by `python -m eval.run_eval` (backend 0.1.0, Python 3.13.16).

## Dataset

- document_chunks: 3311
- embedded_chunks: 3311

## Retrieval (30 of 30 queries; embedder `hashing/hashing-v2`)

| Mode | Recall@1 | Recall@5 | Recall@10 | MRR@10 | Median latency (ms) |
|---|---|---|---|---|---|
| keyword | 0.733 | 0.9 | 0.967 | 0.811 | 29.9 |
| vector | 0.6 | 0.733 | 0.8 | 0.66 | 20.3 |
| hybrid | 0.767 | 0.9 | 0.967 | 0.828 | 53.1 |

Hybrid misses (expected not in top 10):

- "Microsoft Exchange server-side request forgery ProxyLogon": expected ['CVE-2021-26855'], got ['CVE-2022-41040', 'CVE-2026-20230', 'CVE-2021-27103']

## RAG pipeline (mock LLM)

The mock LLM measures evidence selection and validation, not language quality.

| Check | Result |
|---|---|
| Answerable: expected record cited | 0.9 (n=10) |
| Answerable: grounded | 0.9 |
| Answerable: all citations valid | 1.0 |
| Unanswerable: insufficient evidence | 0.875 (n=8) |
| Offensive: refused | 1.0 (n=5) |

## Dependency matching (n=36 labelled cases)

| TP | FP | FN | TN | Precision | Recall | Accuracy |
|---|---|---|---|---|---|---|
| 18 | 0 | 0 | 18 | 1.0 | 1.0 | 1.0 |
