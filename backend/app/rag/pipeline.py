"""Evidence-grounded question answering.

Steps:

1. Validate the question; refuse offensive requests; flag injection-like input.
2. Collect evidence: chunks for CVE IDs named in the question, then hybrid retrieval
   (with the caller's filters). Only evidence with a real match is kept.
3. No relevant evidence: answer "insufficient evidence" without calling the model.
4. Otherwise build a bounded prompt (evidence as delimited, neutralized data) and call
   the LLM. If it is unavailable or times out, return the evidence itself
   (``evidence_only``).
5. Check the output: keep only citations of evidence that was actually provided, flag CVE
   IDs that appear in neither the evidence nor the question, and mark the answer
   ``grounded`` only if it cites evidence and introduces no unsupported identifiers.
6. Attach source facts (CVSS, KEV status, CWEs) read from the database, separate from the
   model's text.
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.db.models import DocumentChunk, KevEntry, Vulnerability, VulnerabilityCwe
from app.llm.providers import LLMProvider, LLMUnavailableError
from app.rag.guardrails import (
    CITATION,
    REFUSAL,
    extract_cve_ids,
    is_offensive_request,
    looks_like_injection,
)
from app.rag.prompt import PROMPT_VERSION, SYSTEM_PROMPT, EvidenceBlock, build_user_message
from app.retrieval.embedders import Embedder
from app.retrieval.search import RetrievalFilters, RetrievedChunk, retrieve

logger = logging.getLogger(__name__)

Mode = Literal["generated", "evidence_only", "insufficient_evidence", "refused"]

DISCLAIMER = (
    "Answers are generated from the cited public sources and may be incomplete or wrong. "
    "Verify facts against the linked records before acting on them."
)
INSUFFICIENT = (
    "The local dataset does not contain enough evidence to answer this question. Try "
    "naming a CVE ID, product or weakness, or ingest the relevant records first."
)
# Cosine distance below which a semantic-model match counts as relevant on its own.
SEMANTIC_RELEVANCE_DISTANCE = 0.55
# A keyword match must cover at least this share of the question's IDF weight, so one
# common word ("today", "system") is not enough to call a chunk relevant.
MIN_KEYWORD_COVERAGE = 0.5
MAX_EVIDENCE = 10


@dataclass
class Citation:
    id: str
    entity_type: str
    entity_id: str
    cve_id: str | None
    title: str
    source_name: str
    source_url: str | None
    snippet: str


@dataclass
class SourceFact:
    cve_id: str
    record_url: str
    severity: str | None
    cvss_base_score: float | None
    cvss_version: str | None
    cvss_provider: str | None
    in_kev: bool
    kev_date_added: str | None
    known_ransomware_use: str | None
    cwes: list[str]


@dataclass
class RagAnswer:
    question: str
    answer: str
    mode: Mode
    grounded: bool
    citations: list[Citation] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    facts: list[SourceFact] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    model: dict[str, str] | None = None
    retrieval: dict[str, Any] = field(default_factory=dict)
    prompt_version: str = PROMPT_VERSION
    latency_ms: float = 0.0
    disclaimer: str = DISCLAIMER


def _is_relevant(chunk: RetrievedChunk, semantic: bool, mentioned: set[str]) -> bool:
    if chunk.cve_id and chunk.cve_id in mentioned:
        return True
    if chunk.keyword_coverage is not None and chunk.keyword_coverage >= MIN_KEYWORD_COVERAGE:
        return True
    return (
        semantic
        and chunk.vector_distance is not None
        and (chunk.vector_distance <= SEMANTIC_RELEVANCE_DISTANCE)
    )


def _chunks_for_cves(session: Session, cve_ids: list[str]) -> list[RetrievedChunk]:
    if not cve_ids:
        return []
    rows = session.scalars(
        select(DocumentChunk)
        .where(DocumentChunk.cve_id.in_(cve_ids))
        .order_by(DocumentChunk.cve_id, DocumentChunk.chunk_index)
    ).all()
    return [
        RetrievedChunk(
            chunk_id=c.id,
            entity_type=c.entity_type,
            entity_id=c.entity_id,
            cve_id=c.cve_id,
            title=c.title,
            content=c.content,
            source_name=c.source_name,
            source_url=c.source_url,
            metadata=dict(c.metadata_ or {}),
            score=1.0,
        )
        for c in rows
    ]


def _facts(session: Session, cve_ids: list[str]) -> list[SourceFact]:
    if not cve_ids:
        return []
    vulns = {
        v.cve_id: v
        for v in session.scalars(select(Vulnerability).where(Vulnerability.cve_id.in_(cve_ids)))
    }
    kev = {
        k.cve_id: k for k in session.scalars(select(KevEntry).where(KevEntry.cve_id.in_(cve_ids)))
    }
    cwes: dict[int, set[str]] = {}
    if vulns:
        for vid, cwe in session.execute(
            select(VulnerabilityCwe.vulnerability_id, VulnerabilityCwe.cwe_id).where(
                VulnerabilityCwe.vulnerability_id.in_([v.id for v in vulns.values()])
            )
        ):
            cwes.setdefault(vid, set()).add(cwe)
    facts = []
    for cve_id in cve_ids:
        v, k = vulns.get(cve_id), kev.get(cve_id)
        if v is None and k is None:
            continue
        facts.append(
            SourceFact(
                cve_id=cve_id,
                record_url=f"https://www.cve.org/CVERecord?id={cve_id}",
                severity=v.severity if v else None,
                cvss_base_score=v.cvss_base_score if v else None,
                cvss_version=v.cvss_version if v else None,
                cvss_provider=v.cvss_provider if v else None,
                in_kev=k is not None,
                kev_date_added=k.date_added.isoformat() if k else None,
                known_ransomware_use=k.known_ransomware_use if k else None,
                cwes=sorted(cwes.get(v.id, set())) if v else list(k.cwes if k else []),
            )
        )
    return facts


def _snippet(text: str, limit: int = 300) -> str:
    body = text.split("\n", 1)[1] if "\n" in text else text
    return body if len(body) <= limit else body[: limit - 1].rstrip() + "…"


def _evidence_only_answer(blocks: list[EvidenceBlock]) -> str:
    lines = [
        "The language model is unavailable, so no generated answer is shown. "
        "The most relevant evidence found is:"
    ]
    lines += [f"- {b.title} ({b.source_name}) [{b.evidence_id}]" for b in blocks[:6]]
    return "\n".join(lines)


def _question_digest(question: str) -> str:
    return hashlib.sha256(question.encode()).hexdigest()[:16]


def answer_question(
    session: Session,
    question: str,
    *,
    settings: Settings,
    embedder: Embedder | None,
    llm: LLMProvider | None,
    filters: RetrievalFilters | None = None,
    top_k: int | None = None,
) -> RagAnswer:
    started = time.perf_counter()
    question = question.strip()
    result = RagAnswer(question=question, answer="", mode="insufficient_evidence", grounded=False)

    def finish() -> RagAnswer:
        result.latency_ms = round((time.perf_counter() - started) * 1000, 1)
        logger.info(
            "RAG answer",
            extra={
                "question_sha": _question_digest(question),
                "mode": result.mode,
                "grounded": result.grounded,
                "citations": len(result.citations),
                "latency_ms": result.latency_ms,
            },
        )
        return result

    if is_offensive_request(question):
        result.mode, result.answer = "refused", REFUSAL
        return finish()
    if looks_like_injection(question):
        result.warnings.append(
            "The question contains instruction-like text; it was treated as a question only."
        )

    mentioned = extract_cve_ids(question)
    k = top_k or settings.rag_top_k
    retrieval = retrieve(session, question, embedder, k=k, filters=filters, max_chunks_per_entity=2)
    result.retrieval = {
        "mode": retrieval.mode,
        "embedding_model": retrieval.embedding_model,
        "semantic": retrieval.semantic_model,
    }
    result.warnings.extend(w for w in retrieval.warnings if "lexical" not in w)

    exact = _chunks_for_cves(session, mentioned)
    missing = [c for c in mentioned if c not in {x.cve_id for x in exact}]
    if missing:
        result.warnings.append("Not in the local dataset: " + ", ".join(missing) + ".")
    ordered: dict[int, RetrievedChunk] = {c.chunk_id: c for c in exact}
    for chunk in retrieval.chunks:
        if _is_relevant(chunk, retrieval.semantic_model, set(mentioned)):
            ordered.setdefault(chunk.chunk_id, chunk)
    chunks = list(ordered.values())[:MAX_EVIDENCE]
    if not chunks:
        result.answer = INSUFFICIENT
        return finish()

    blocks = [
        EvidenceBlock(
            evidence_id=f"E{i}",
            title=c.title,
            source_name=c.source_name,
            source_url=c.source_url,
            cve_id=c.cve_id,
            text=c.content,
        )
        for i, c in enumerate(chunks, start=1)
    ]
    user_message, used_blocks = build_user_message(question, blocks, settings.rag_max_context_chars)
    by_id = {b.evidence_id: (b, c) for b, c in zip(blocks, chunks, strict=True)}
    if any(looks_like_injection(b.text) for b in used_blocks):
        result.warnings.append(
            "Some retrieved text contains instruction-like content; it was "
            "provided to the model as data only."
        )
    evidence_cves = {b.cve_id for b in used_blocks if b.cve_id}

    cited_ids: list[str]
    if llm is None:
        result.mode = "evidence_only"
        result.answer = _evidence_only_answer(used_blocks)
        result.warnings.append(
            (settings.gemini_problem("llm") if settings.llm_provider == "gemini" else None)
            or f"No language model is configured (LLM_PROVIDER={settings.llm_provider})."
        )
        cited_ids = [b.evidence_id for b in used_blocks[:6]]
    else:
        try:
            generated = llm.generate(SYSTEM_PROMPT, user_message)
        except LLMUnavailableError as exc:
            result.mode = "evidence_only"
            result.answer = _evidence_only_answer(used_blocks)
            result.warnings.append(f"Language model unavailable: {exc}.")
            cited_ids = [b.evidence_id for b in used_blocks[:6]]
        else:
            result.mode = "generated"
            result.model = {"provider": generated.provider, "name": generated.model}
            text = generated.text[: settings.rag_max_answer_chars]
            if generated.truncated or len(generated.text) > settings.rag_max_answer_chars:
                result.warnings.append("The answer was cut at the length limit.")
            valid = {b.evidence_id for b in used_blocks}
            cited_ids = list(dict.fromkeys(m for m in CITATION.findall(text) if m in valid))
            invalid = sorted({m for m in CITATION.findall(text) if m not in valid})
            if invalid:
                text = CITATION.sub(
                    lambda m: (
                        m.group(0) if m.group(1) in valid else "[unsupported citation removed]"
                    ),
                    text,
                )
                result.warnings.append(
                    "Removed citations to evidence that was not provided: "
                    + ", ".join(invalid)
                    + "."
                )
            unsupported = [
                c for c in extract_cve_ids(text) if c not in evidence_cves and c not in mentioned
            ]
            if unsupported:
                result.warnings.append(
                    "The answer mentions CVE IDs that are not in the "
                    "evidence: " + ", ".join(unsupported) + ". Treat them "
                    "as unverified."
                )
            if not cited_ids:
                result.warnings.append("The answer cites no evidence; treat it as unverified.")
            result.grounded = bool(cited_ids) and not unsupported
            result.answer = text

    for eid in cited_ids:
        block, chunk = by_id[eid]
        result.citations.append(
            Citation(
                id=eid,
                entity_type=chunk.entity_type,
                entity_id=chunk.entity_id,
                cve_id=chunk.cve_id,
                title=block.title,
                source_name=block.source_name,
                source_url=block.source_url,
                snippet=_snippet(chunk.content),
            )
        )
    result.cve_ids = list(dict.fromkeys(c.cve_id for c in result.citations if c.cve_id))
    result.facts = _facts(session, list(dict.fromkeys(mentioned + result.cve_ids)))
    return finish()
