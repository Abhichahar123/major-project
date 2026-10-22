"""Hybrid retrieval over document chunks.

Two ranked lists are fused with reciprocal rank fusion (RRF, k=60):

* keyword: PostgreSQL full-text search (``websearch_to_tsquery``, ``ts_rank_cd``);
* vector: pgvector cosine distance with the configured embedding model.

Metadata filters (severity, KEV membership, entity type, CVE IDs) apply to both lists.
When no embedder is configured, the model is unreachable, or no vectors exist for it,
search degrades to keyword-only and says so in ``warnings``.
"""

from __future__ import annotations

import bisect
import math
import threading
from dataclasses import dataclass, field
from typing import Any, Literal

from sqlalchemy import Select, case, func, literal, select, text
from sqlalchemy.orm import Session

from app.db.models import ChunkEmbedding, DocumentChunk
from app.retrieval.embedders import Embedder, EmbeddingUnavailableError
from app.retrieval.indexer import find_model_id

RRF_K = 60
CANDIDATES = 50
# Fusion weight of the vector list. A lexical (hashing) embedder repeats the keyword signal
# without IDF, so its list only breaks ties and adds candidates the keyword list missed;
# a semantic model contributes with full weight. Measured in backend/eval (retrieval).
VECTOR_WEIGHT_SEMANTIC = 1.0
VECTOR_WEIGHT_LEXICAL = 0.02
EXACT_SEARCH_MAX_VECTORS = 20_000

Mode = Literal["hybrid", "semantic", "keyword"]


@dataclass
class RetrievalFilters:
    severity: list[str] = field(default_factory=list)
    in_kev: bool | None = None
    entity_types: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)


@dataclass
class RetrievedChunk:
    chunk_id: int
    entity_type: str
    entity_id: str
    cve_id: str | None
    title: str
    content: str
    source_name: str
    source_url: str | None
    metadata: dict[str, Any]
    score: float
    keyword_rank: int | None = None
    vector_rank: int | None = None
    vector_distance: float | None = None
    # Share of the query's total IDF weight matched by this chunk (keyword list only).
    keyword_coverage: float | None = None


@dataclass
class RetrievalResult:
    chunks: list[RetrievedChunk]
    mode: Mode
    vector_used: bool
    embedding_model: str | None
    semantic_model: bool
    warnings: list[str] = field(default_factory=list)


def _apply_filters(stmt: Select[Any], f: RetrievalFilters) -> Select[Any]:
    if f.entity_types:
        stmt = stmt.where(DocumentChunk.entity_type.in_(f.entity_types))
    if f.cve_ids:
        stmt = stmt.where(DocumentChunk.cve_id.in_(f.cve_ids))
    if f.severity:
        stmt = stmt.where(DocumentChunk.metadata_["severity"].astext.in_(f.severity))
    if f.in_kev is not None:
        stmt = stmt.where(
            DocumentChunk.metadata_["in_kev"].astext == ("true" if f.in_kev else "false")
        )
    return stmt


class _TermStats:
    """Document frequencies of chunk lexemes (from ``ts_stat``), cached per corpus size."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._size = -1
        self._words: list[str] = []
        self._ndoc: list[int] = []
        self.total = 0

    def refresh(self, session: Session) -> None:
        size = session.scalar(select(func.count()).select_from(DocumentChunk)) or 0
        with self._lock:
            if size == self._size:
                return
            rows = sorted(
                session.execute(
                    text("SELECT word, ndoc FROM ts_stat('SELECT tsv FROM document_chunks')")
                ).all()
            )  # sorted in Python: bisect needs code-point order, not the DB collation
            self._words = [w for w, _ in rows]
            self._ndoc = [n for _, n in rows]
            self._size = self.total = size

    def exact_df(self, lexeme: str) -> int:
        i = bisect.bisect_left(self._words, lexeme)
        return self._ndoc[i] if i < len(self._words) and self._words[i] == lexeme else 0

    def prefix_df(self, lexeme: str) -> int:
        """Chunks containing a word starting with ``lexeme`` (upper bound: summed df)."""
        lo = bisect.bisect_left(self._words, lexeme)
        hi = bisect.bisect_left(self._words, lexeme + "\uffff")
        return min(self.total, sum(self._ndoc[lo:hi]))


TERM_STATS = _TermStats()


def _quote_lexeme(lexeme: str) -> str:
    return "'" + lexeme.replace("\\", "\\\\").replace("'", "''") + "'"


def keyword_candidates(
    session: Session, query: str, f: RetrievalFilters, limit: int = CANDIDATES
) -> list[tuple[DocumentChunk, float, float]]:
    """Any-term full-text retrieval ranked by summed IDF of the matched query terms.

    Returns (chunk, score, coverage), where coverage is the share of the query's total
    IDF weight that the chunk matches (0-1).

    Query lexemes (English-stemmed) match as prefixes, so "log4j" also finds "log4j2".
    Ranking by IDF lets rare, specific terms outweigh common ones such as "remote" or
    "code"; ``ts_rank_cd`` breaks ties.
    """
    lexemes = list(
        dict.fromkeys(
            session.scalars(
                select(func.unnest(func.tsvector_to_array(func.to_tsvector("english", query))))
            )
        )
    )[:20]
    if not lexemes:
        return []
    TERM_STATS.refresh(session)
    n = max(TERM_STATS.total, 1)
    terms = []
    for lexeme in lexemes:
        pattern = _quote_lexeme(lexeme) + (":*" if len(lexeme) >= 4 else "")
        df = TERM_STATS.prefix_df(lexeme) if len(lexeme) >= 4 else TERM_STATS.exact_df(lexeme)
        idf = math.log((n - df + 0.5) / (df + 0.5) + 1.0)
        terms.append((func.to_tsquery("simple", pattern), idf))
    any_term = func.to_tsquery(
        "simple", " | ".join(_quote_lexeme(lx) + (":*" if len(lx) >= 4 else "") for lx in lexemes)
    )
    idf_score = sum(
        (case((DocumentChunk.tsv.op("@@")(tq), idf), else_=0.0) for tq, idf in terms),
        start=literal(0.0),
    )
    score = idf_score + 0.1 * func.ts_rank_cd(DocumentChunk.tsv, any_term)
    total_idf = sum(idf for _, idf in terms) or 1.0
    stmt = select(DocumentChunk, score.label("score"), idf_score.label("idf")).where(
        DocumentChunk.tsv.op("@@")(any_term)
    )
    rows = session.execute(
        _apply_filters(stmt, f).order_by(score.desc(), DocumentChunk.id).limit(limit)
    ).all()
    return [(chunk, float(sc), round(float(idf) / total_idf, 4)) for chunk, sc, idf in rows]


def vector_candidates(
    session: Session,
    vector: list[float],
    model_id: int,
    f: RetrievalFilters,
    limit: int = CANDIDATES,
) -> list[tuple[DocumentChunk, float]]:
    """Nearest chunks by cosine distance for one embedding model.

    Up to ``EXACT_SEARCH_MAX_VECTORS`` vectors an exact scan is used: it is fast at that
    size and, unlike an approximate HNSW scan followed by a model/metadata filter, it
    cannot lose matches. Larger corpora use the HNSW index.
    """
    distance = ChunkEmbedding.embedding.cosine_distance(vector)
    stmt = (
        select(DocumentChunk, distance.label("distance"))
        .join(ChunkEmbedding, ChunkEmbedding.chunk_id == DocumentChunk.id)
        .where(ChunkEmbedding.model_id == model_id)
    )
    stmt = _apply_filters(stmt, f).order_by(distance).limit(limit)
    size = (
        session.scalar(
            select(func.count())
            .select_from(ChunkEmbedding)
            .where(ChunkEmbedding.model_id == model_id)
        )
        or 0
    )
    if size <= EXACT_SEARCH_MAX_VECTORS:
        session.execute(text("SET LOCAL enable_indexscan = off"))
        try:
            rows = session.execute(stmt).all()
        finally:
            session.execute(text("SET LOCAL enable_indexscan = on"))
    else:
        # A larger candidate list keeps recall when filters remove index hits.
        session.execute(text("SET LOCAL hnsw.ef_search = 200"))
        rows = session.execute(stmt).all()
    return [(chunk, float(d)) for chunk, d in rows]


def retrieve(
    session: Session,
    query: str,
    embedder: Embedder | None,
    *,
    k: int = 8,
    mode: Mode = "hybrid",
    filters: RetrievalFilters | None = None,
    max_chunks_per_entity: int | None = None,
) -> RetrievalResult:
    f = filters or RetrievalFilters()
    warnings: list[str] = []
    vector_hits: list[tuple[DocumentChunk, float]] = []
    vector_used = False

    if mode in {"hybrid", "semantic"}:
        if embedder is None:
            warnings.append(
                "Semantic retrieval is disabled (EMBEDDING_PROVIDER=none); using keyword search."
            )
        else:
            model_id = find_model_id(session, embedder)
            if model_id is None:
                warnings.append(
                    f"No embeddings stored for {embedder.provider}/{embedder.name}; "
                    "run the embeddings job. Using keyword search."
                )
            else:
                try:
                    vector = embedder.embed_query(query)
                except EmbeddingUnavailableError as exc:
                    warnings.append(f"{exc} Using keyword search.")
                else:
                    vector_hits = vector_candidates(session, vector, model_id, f)
                    vector_used = True
            if vector_used and not embedder.semantic:
                warnings.append(
                    "The configured embedder is lexical (hashing), not a semantic "
                    "model; results reflect shared terms only."
                )

    keyword_hits: list[tuple[DocumentChunk, float, float]] = []
    if mode in {"hybrid", "keyword"} or not vector_used:
        keyword_hits = keyword_candidates(session, query, f)

    fused: dict[int, RetrievedChunk] = {}

    vector_weight = (
        VECTOR_WEIGHT_SEMANTIC if embedder and embedder.semantic else VECTOR_WEIGHT_LEXICAL
    )

    def add(
        chunk: DocumentChunk,
        rank: int,
        *,
        keyword: bool,
        distance: float | None,
        coverage: float | None = None,
    ) -> None:
        item = fused.get(chunk.id)
        if item is None:
            item = fused[chunk.id] = RetrievedChunk(
                chunk_id=chunk.id,
                entity_type=chunk.entity_type,
                entity_id=chunk.entity_id,
                cve_id=chunk.cve_id,
                title=chunk.title,
                content=chunk.content,
                source_name=chunk.source_name,
                source_url=chunk.source_url,
                metadata=dict(chunk.metadata_ or {}),
                score=0.0,
            )
        item.score += (1.0 if keyword else vector_weight) / (RRF_K + rank)
        if keyword:
            item.keyword_rank, item.keyword_coverage = rank, coverage
        else:
            item.vector_rank, item.vector_distance = rank, round(distance or 0.0, 4)

    for rank, (chunk, _, coverage) in enumerate(keyword_hits, start=1):
        add(chunk, rank, keyword=True, distance=None, coverage=coverage)
    for rank, (chunk, distance) in enumerate(vector_hits, start=1):
        add(chunk, rank, keyword=False, distance=distance)

    ranked_all = sorted(fused.values(), key=lambda c: (-c.score, c.chunk_id))
    if max_chunks_per_entity:
        per_entity: dict[tuple[str, str], int] = {}
        kept = []
        for item in ranked_all:
            key = (item.entity_type, item.entity_id)
            if per_entity.get(key, 0) < max_chunks_per_entity:
                per_entity[key] = per_entity.get(key, 0) + 1
                kept.append(item)
        ranked_all = kept
    ranked = ranked_all[:k]
    for item in ranked:
        item.score = round(item.score, 6)
    effective: Mode = mode if vector_used or mode == "keyword" else "keyword"
    return RetrievalResult(
        chunks=ranked,
        mode=effective,
        vector_used=vector_used,
        embedding_model=f"{embedder.provider}/{embedder.name}"
        if embedder and vector_used
        else None,
        semantic_model=bool(embedder and vector_used and embedder.semantic),
        warnings=warnings,
    )
