"""Evaluate retrieval, the RAG pipeline and dependency matching against ingested data.

Usage (from backend/, with DATABASE_URL pointing at a seeded and indexed database)::

    python -m eval.run_eval            # writes eval/results/latest.json and .md

What is measured:

* retrieval: Recall@1/5/10 and MRR@10 of the expected entity, for keyword, vector and
  hybrid modes, with the embedder configured by EMBEDDING_PROVIDER;
* RAG pipeline: with the deterministic mock LLM, so this measures evidence selection,
  citation validity, refusal and insufficient-evidence behaviour, not language quality;
* dependency matching: confusion matrix on labelled (package, version, CVE) cases.

Expected IDs missing from the database are reported and excluded from the metrics, so
results describe the system on the data it has.
"""

from __future__ import annotations

import json
import platform
import statistics
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import func, select

from app import __version__
from app.core.config import load_settings
from app.db.models import ChunkEmbedding, DocumentChunk
from app.dependencies.matcher import analyze
from app.dependencies.parsers import Dependency, Manifest
from app.ingestion.normalize import normalize_package_name
from app.ingestion.runtime import make_ingestion_engine, make_session_factory
from app.llm.providers import MockProvider
from app.rag.guardrails import CITATION
from app.rag.pipeline import answer_question
from app.retrieval.embedders import build_embedder
from app.retrieval.search import retrieve

HERE = Path(__file__).resolve().parent
K = 10


def _load(name: str) -> Any:
    return json.loads((HERE / name).read_text())


def eval_retrieval(session: Any, embedder: Any) -> dict[str, Any]:
    queries = _load("golden_retrieval.json")["queries"]
    known = set(session.scalars(select(DocumentChunk.entity_id).distinct()))
    usable = [q for q in queries if set(q["expected"]) & known]
    missing = [q["q"] for q in queries if not set(q["expected"]) & known]
    out: dict[str, Any] = {
        "queries_total": len(queries),
        "queries_used": len(usable),
        "excluded_not_in_dataset": missing,
        "modes": {},
    }
    for mode in ("keyword", "semantic", "hybrid"):
        ranks: list[int | None] = []
        latencies: list[float] = []
        per_query = []
        for item in usable:
            started = time.perf_counter()
            result = retrieve(session, item["q"], embedder, k=K, mode=mode, max_chunks_per_entity=1)
            latencies.append((time.perf_counter() - started) * 1000)
            ids = [c.entity_id for c in result.chunks]
            rank = next((i + 1 for i, e in enumerate(ids) if e in item["expected"]), None)
            ranks.append(rank)
            per_query.append(
                {
                    "q": item["q"],
                    "expected": item["expected"],
                    "rank": rank,
                    "top3": ids[:3],
                    "effective_mode": result.mode,
                }
            )
        n = len(ranks) or 1
        out["modes"]["vector" if mode == "semantic" else mode] = {
            "recall_at_1": round(sum(1 for r in ranks if r == 1) / n, 3),
            "recall_at_5": round(sum(1 for r in ranks if r and r <= 5) / n, 3),
            "recall_at_10": round(sum(1 for r in ranks if r and r <= K) / n, 3),
            "mrr_at_10": round(sum(1 / r for r in ranks if r) / n, 3),
            "median_latency_ms": round(statistics.median(latencies), 1) if latencies else None,
            "per_query": per_query,
        }
    return out


def eval_rag(session: Any, settings: Any, embedder: Any) -> dict[str, Any]:
    golden = _load("golden_rag.json")
    llm = MockProvider()
    answerable = []
    for item in golden["answerable"]:
        res = answer_question(session, item["q"], settings=settings, embedder=embedder, llm=llm)
        cited = {c.entity_id for c in res.citations}
        provided_ids = {c.id for c in res.citations}
        raw_citations = set(CITATION.findall(res.answer))
        answerable.append(
            {
                "q": item["q"],
                "mode": res.mode,
                "grounded": res.grounded,
                "expected_cited": bool(set(item["expected"]) & cited),
                "citations_valid": raw_citations <= provided_ids | {"unsupported citation removed"},
                "cited": sorted(cited),
            }
        )
    unanswerable = []
    for q in golden["unanswerable"]:
        res = answer_question(session, q, settings=settings, embedder=embedder, llm=llm)
        unanswerable.append({"q": q, "mode": res.mode})
    offensive = []
    for q in golden["offensive"]:
        res = answer_question(session, q, settings=settings, embedder=embedder, llm=llm)
        offensive.append({"q": q, "mode": res.mode})

    def rate(items: list[dict[str, Any]], pred: Any) -> float:
        return round(sum(1 for i in items if pred(i)) / (len(items) or 1), 3)

    return {
        "llm": "mock (deterministic); measures the pipeline, not a language model",
        "answerable": {
            "n": len(answerable),
            "expected_record_cited_rate": rate(answerable, lambda i: i["expected_cited"]),
            "grounded_rate": rate(answerable, lambda i: i["grounded"]),
            "all_citations_valid_rate": rate(answerable, lambda i: i["citations_valid"]),
            "items": answerable,
        },
        "unanswerable": {
            "n": len(unanswerable),
            "insufficient_evidence_rate": rate(
                unanswerable, lambda i: i["mode"] == "insufficient_evidence"
            ),
            "items": unanswerable,
        },
        "offensive": {
            "n": len(offensive),
            "refusal_rate": rate(offensive, lambda i: i["mode"] == "refused"),
            "items": offensive,
        },
    }


def eval_dependencies(session: Any) -> dict[str, Any]:
    cases = _load("golden_dependencies.json")["cases"]
    tp = fp = fn = tn = uncertain_only = 0
    details = []
    for case in cases:
        dep = Dependency(
            name=case["name"],
            normalized_name=normalize_package_name(case["ecosystem"], case["name"]),
            ecosystem=case["ecosystem"],
            version=case["version"],
            specifier=None,
            pinned=True,
            location="eval",
        )
        manifest = Manifest(
            format="requirements.txt" if case["ecosystem"] == "PyPI" else "package-lock.json",
            ecosystem=case["ecosystem"],
            dependencies=[dep],
        )
        report = analyze(session, manifest)
        confirmed = any(
            f.confidence == "confirmed" and case["cve"] in f.cve_ids for f in report.findings
        )
        uncertain = any(
            f.confidence == "uncertain" and case["cve"] in f.cve_ids for f in report.findings
        )
        if confirmed and case["affected"]:
            tp += 1
        elif confirmed:
            fp += 1
        elif case["affected"]:
            fn += 1
            uncertain_only += int(uncertain)
        else:
            tn += 1
        details.append({**case, "predicted_confirmed": confirmed, "uncertain": uncertain})
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    return {
        "n": len(cases),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "false_negatives_reported_as_uncertain": uncertain_only,
        "precision": round(precision, 3) if precision is not None else None,
        "recall": round(recall, 3) if recall is not None else None,
        "accuracy": round((tp + tn) / len(cases), 3),
        "items": details,
    }


def _markdown(report: dict[str, Any]) -> str:
    r, g, d = report["retrieval"], report["rag"], report["dependencies"]
    lines = [
        "# Evaluation results",
        "",
        f"Generated {report['generated_at']} by `python -m eval.run_eval` "
        f"(backend {report['backend_version']}, Python {report['python']}).",
        "",
        "## Dataset",
        "",
        *[f"- {k}: {v}" for k, v in report["dataset"].items()],
        "",
        f"## Retrieval ({r['queries_used']} of {r['queries_total']} queries; "
        f"embedder `{report['embedder']}`)",
        "",
        "| Mode | Recall@1 | Recall@5 | Recall@10 | MRR@10 | Median latency (ms) |",
        "|---|---|---|---|---|---|",
    ]
    for mode, m in r["modes"].items():
        lines.append(
            f"| {mode} | {m['recall_at_1']} | {m['recall_at_5']} | {m['recall_at_10']} "
            f"| {m['mrr_at_10']} | {m['median_latency_ms']} |"
        )
    if r["excluded_not_in_dataset"]:
        lines += [
            "",
            "Excluded (expected record not ingested): " + "; ".join(r["excluded_not_in_dataset"]),
        ]
    misses = [p for p in r["modes"]["hybrid"]["per_query"] if not p["rank"]]
    if misses:
        lines += ["", "Hybrid misses (expected not in top 10):", ""]
        lines += [f'- "{p["q"]}": expected {p["expected"]}, got {p["top3"]}' for p in misses]
    lines += [
        "",
        "## RAG pipeline (mock LLM: measures evidence selection and validation, not language quality)",
        "",
        "| Check | Result |",
        "|---|---|",
        f"| Answerable: expected record cited | {g['answerable']['expected_record_cited_rate']} "
        f"(n={g['answerable']['n']}) |",
        f"| Answerable: grounded | {g['answerable']['grounded_rate']} |",
        f"| Answerable: all citations valid | {g['answerable']['all_citations_valid_rate']} |",
        f"| Unanswerable: insufficient evidence | {g['unanswerable']['insufficient_evidence_rate']} "
        f"(n={g['unanswerable']['n']}) |",
        f"| Offensive: refused | {g['offensive']['refusal_rate']} (n={g['offensive']['n']}) |",
        "",
        f"## Dependency matching (n={d['n']} labelled cases)",
        "",
        "| TP | FP | FN | TN | Precision | Recall | Accuracy |",
        "|---|---|---|---|---|---|---|",
        f"| {d['tp']} | {d['fp']} | {d['fn']} | {d['tn']} | {d['precision']} | {d['recall']} "
        f"| {d['accuracy']} |",
    ]
    wrong = [i for i in d["items"] if i["predicted_confirmed"] != i["affected"]]
    if wrong:
        lines += ["", "Disagreements:", ""]
        lines += [
            f"- {i['ecosystem']} {i['name']} {i['version']} / {i['cve']}: labelled "
            f"{'affected' if i['affected'] else 'not affected'}, predicted "
            f"{'affected' if i['predicted_confirmed'] else 'not affected'}"
            + (" (reported as uncertain)" if i["uncertain"] else "")
            for i in wrong
        ]
    return "\n".join(lines) + "\n"


def main() -> int:
    settings = load_settings()
    engine = make_ingestion_engine(settings)
    session_factory = make_session_factory(engine)
    embedder = build_embedder(settings)
    with session_factory() as session:
        dataset = {
            "document_chunks": session.scalar(select(func.count()).select_from(DocumentChunk)),
            "embedded_chunks": session.scalar(select(func.count()).select_from(ChunkEmbedding)),
        }
        report = {
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "backend_version": __version__,
            "python": platform.python_version(),
            "embedder": f"{embedder.provider}/{embedder.name}" if embedder else "none",
            "dataset": dataset,
            "retrieval": eval_retrieval(session, embedder),
            "rag": eval_rag(session, settings, embedder),
            "dependencies": eval_dependencies(session),
        }
    engine.dispose()
    out = HERE / "results"
    out.mkdir(exist_ok=True)
    (out / "latest.json").write_text(json.dumps(report, indent=2, default=str))
    (out / "latest.md").write_text(_markdown(report))
    print(_markdown(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
