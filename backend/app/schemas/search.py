"""Semantic / hybrid search schemas."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel


class SearchHit(BaseModel):
    chunk_id: int
    entity_type: str
    entity_id: str
    cve_id: str | None
    title: str
    snippet: str
    source_name: str
    source_url: str | None
    metadata: dict[str, Any]
    score: float
    keyword_rank: int | None
    vector_rank: int | None
    vector_distance: float | None


class SearchResponse(BaseModel):
    query: str
    mode: Literal["hybrid", "semantic", "keyword"]
    vector_used: bool
    embedding_model: str | None
    semantic_model: bool
    warnings: list[str]
    results: list[SearchHit]
