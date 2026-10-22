"""The ``embeddings`` job: rebuild document chunks, then embed what is missing.

Embeddings are keyed by (chunk, model) and store the chunk's content hash, so re-running
the job only embeds new or changed chunks for the configured model. With ``prune`` (the
default), other models' vectors are deleted only after every chunk has been embedded with
the configured model, so a failed or rate-limited run never leaves search without vectors.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import and_, delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.db.models import ChunkEmbedding, DocumentChunk, EmbeddingModel
from app.ingestion.jobs import JobContext
from app.ingestion.sources import ParamError, _bool_param, _reject_unknown
from app.retrieval.documents import DOCUMENT_BUILDERS, sync_documents
from app.retrieval.embedders import Embedder, EmbeddingUnavailableError, build_embedder


def get_or_create_model(session: Session, embedder: Embedder) -> int:
    stmt = (
        insert(EmbeddingModel)
        .values(provider=embedder.provider, name=embedder.name, dimension=embedder.dimension)
        .on_conflict_do_nothing()
    )
    session.execute(stmt)
    model_id = session.scalar(
        select(EmbeddingModel.id).where(
            EmbeddingModel.provider == embedder.provider,
            EmbeddingModel.name == embedder.name,
            EmbeddingModel.dimension == embedder.dimension,
        )
    )
    if model_id is None:  # pragma: no cover - the insert above guarantees a row
        raise RuntimeError("embedding model row could not be created")
    return model_id


def find_model_id(session: Session, embedder: Embedder) -> int | None:
    return session.scalar(
        select(EmbeddingModel.id).where(
            EmbeddingModel.provider == embedder.provider,
            EmbeddingModel.name == embedder.name,
            EmbeddingModel.dimension == embedder.dimension,
        )
    )


class EmbeddingsAdapter:
    code = "embeddings"

    def __init__(self, embedder: Embedder | None = None) -> None:
        self._embedder = embedder

    def validate_params(self, params: dict[str, Any]) -> dict[str, Any]:
        _reject_unknown(params, {"entity_types", "reembed", "prune"})
        types = params.get("entity_types", list(DOCUMENT_BUILDERS))
        if not isinstance(types, list) or not types or not set(types) <= set(DOCUMENT_BUILDERS):
            raise ParamError(f"entity_types must be a subset of {sorted(DOCUMENT_BUILDERS)}")
        return {
            "entity_types": types,
            "reembed": _bool_param(params, "reembed", False),
            # One model per index keeps approximate (HNSW) search accurate; see search.py.
            "prune": _bool_param(params, "prune", True),
        }

    def run(self, ctx: JobContext) -> None:
        embedder = self._embedder or build_embedder(ctx.settings)
        with ctx.session_factory.begin() as session:
            result = sync_documents(session, ctx.params["entity_types"])
        ctx.details.update(
            {
                "documents": result.documents,
                "chunks_written": result.chunks_written,
                "chunks_unchanged": result.chunks_unchanged,
                "chunks_removed": result.chunks_removed,
            }
        )
        if embedder is None:
            ctx.details["embedding"] = (
                ctx.settings.gemini_problem("embedding")
                if ctx.settings.embedding_provider == "gemini"
                else None
            ) or f"disabled (EMBEDDING_PROVIDER={ctx.settings.embedding_provider})"
            return
        ctx.details.update(
            {
                "embedding_provider": embedder.provider,
                "embedding_model": embedder.name,
                "semantic": embedder.semantic,
            }
        )

        with ctx.session_factory.begin() as session:
            model_id = get_or_create_model(session, embedder)
            if ctx.params["reembed"]:
                session.execute(delete(ChunkEmbedding).where(ChunkEmbedding.model_id == model_id))
            todo = session.execute(
                select(
                    DocumentChunk.id,
                    DocumentChunk.content,
                    DocumentChunk.content_hash,
                    ChunkEmbedding.content_hash,
                )
                .outerjoin(
                    ChunkEmbedding,
                    and_(
                        ChunkEmbedding.chunk_id == DocumentChunk.id,
                        ChunkEmbedding.model_id == model_id,
                    ),
                )
                .order_by(DocumentChunk.id)
            ).all()
        ctx.fetched = len(todo)
        pending = []
        for chunk_id, content, digest, embedded_digest in todo:
            if embedded_digest == digest:
                ctx.unchanged += 1
            else:
                pending.append((chunk_id, content, digest, embedded_digest is not None))

        batch_size = ctx.settings.embedding_batch_size
        complete = True
        for start in range(0, len(pending), batch_size):
            batch = pending[start : start + batch_size]
            try:
                vectors = embedder.embed_documents([content for _, content, _, _ in batch])
            except EmbeddingUnavailableError as exc:
                for chunk_id, *_ in batch:
                    ctx.fail(str(chunk_id), "embed", str(exc))
                # The backend is down: stop instead of failing every remaining batch.
                remaining = len(pending) - start - len(batch)
                ctx.details["not_attempted"] = remaining
                complete = False
                break
            with ctx.session_factory.begin() as session:
                for (chunk_id, _, digest, existed), vector in zip(batch, vectors, strict=True):
                    stmt = (
                        insert(ChunkEmbedding)
                        .values(
                            chunk_id=chunk_id,
                            model_id=model_id,
                            content_hash=digest,
                            embedding=vector,
                        )
                        .on_conflict_do_update(
                            index_elements=[ChunkEmbedding.chunk_id, ChunkEmbedding.model_id],
                            set_={"content_hash": digest, "embedding": vector},
                        )
                    )
                    session.execute(stmt)
                    if existed:
                        ctx.updated += 1
                    else:
                        ctx.inserted += 1
            ctx.flush_progress()

        if ctx.params["prune"]:
            if complete:
                with ctx.session_factory.begin() as session:
                    session.execute(
                        delete(ChunkEmbedding).where(ChunkEmbedding.model_id != model_id)
                    )
            else:
                ctx.details["prune"] = "skipped: not every chunk was embedded"
