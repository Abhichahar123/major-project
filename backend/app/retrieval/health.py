"""Readiness probe for semantic retrieval (reported as degraded, never fatal)."""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, select

from app.api.routes.health import ReadinessCheck
from app.db.models import ChunkEmbedding
from app.retrieval.indexer import find_model_id


def embedding_probe(app: Any) -> ReadinessCheck:
    embedder = app.state.embedder
    if embedder is None:
        return ReadinessCheck(status="degraded", detail="disabled; keyword search only")
    label = f"{embedder.provider}/{embedder.name}"
    try:
        with app.state.db_session_factory() as session:
            model_id = find_model_id(session, embedder)
            count = (
                0
                if model_id is None
                else session.scalar(
                    select(func.count())
                    .select_from(ChunkEmbedding)
                    .where(ChunkEmbedding.model_id == model_id)
                )
                or 0
            )
    except Exception:
        return ReadinessCheck(status="degraded", detail=f"{label}: could not query embeddings")
    if count == 0:
        return ReadinessCheck(
            status="degraded", detail=f"{label}: no embeddings yet; run the embeddings job"
        )
    note = "" if embedder.semantic else " (lexical, not semantic)"
    return ReadinessCheck(status="ok", detail=f"{label}: {count} chunks{note}")
