"""Hybrid (keyword + vector) retrieval over vulnerability, KEV and ATT&CK documents."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Request

from app.api.deps import DbSession
from app.core.rate_limit import rate_limit
from app.retrieval.search import RetrievalFilters, retrieve
from app.schemas.common import Severity
from app.schemas.search import SearchHit, SearchResponse

router = APIRouter(tags=["search"], dependencies=[Depends(rate_limit("search"))])

EntityType = Literal["vulnerability", "kev", "attack_technique"]
SNIPPET = 400


@router.get("/search", response_model=SearchResponse)
def semantic_search(
    request: Request,
    db: DbSession,
    q: Annotated[str, Query(min_length=2, max_length=500)],
    mode: Literal["hybrid", "semantic", "keyword"] = "hybrid",
    k: Annotated[int, Query(ge=1, le=50)] = 10,
    severity: Annotated[list[Severity], Query()] = [],  # noqa: B006
    in_kev: bool | None = None,
    entity_type: Annotated[list[EntityType], Query()] = [],  # noqa: B006
) -> SearchResponse:
    """Ranked evidence chunks. ``mode=hybrid`` fuses keyword and vector rankings; the
    response states which embedding model was used and whether it is semantic."""
    filters = RetrievalFilters(
        severity=list(severity), in_kev=in_kev, entity_types=list(entity_type)
    )
    result = retrieve(
        db,
        q,
        request.app.state.embedder,
        k=k,
        mode=mode,
        filters=filters,
        max_chunks_per_entity=1,
    )
    return SearchResponse(
        query=q,
        mode=result.mode,
        vector_used=result.vector_used,
        embedding_model=result.embedding_model,
        semantic_model=result.semantic_model,
        warnings=result.warnings,
        results=[
            SearchHit(
                chunk_id=c.chunk_id,
                entity_type=c.entity_type,
                entity_id=c.entity_id,
                cve_id=c.cve_id,
                title=c.title,
                snippet=c.content if len(c.content) <= SNIPPET else c.content[:SNIPPET] + "…",
                source_name=c.source_name,
                source_url=c.source_url,
                metadata=c.metadata,
                score=c.score,
                keyword_rank=c.keyword_rank,
                vector_rank=c.vector_rank,
                vector_distance=c.vector_distance,
            )
            for c in result.chunks
        ],
    )
