"""Embeddings job and hybrid retrieval against a real pgvector database."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.db.models import ChunkEmbedding, DocumentChunk, EmbeddingModel, Vulnerability
from app.ingestion.jobs import run_now
from app.main import create_app
from app.retrieval.embedders import EmbeddingUnavailableError, HashingEmbedder
from app.retrieval.indexer import EmbeddingsAdapter
from app.retrieval.search import RetrievalFilters, retrieve
from tests.integration.helpers import (
    FakeUpstream,
    http_factory_for,
    seed_fixture_data,
    source_settings,
)

pytestmark = pytest.mark.integration


class BrokenEmbedder(HashingEmbedder):
    provider = "test"
    name = "broken"

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        raise EmbeddingUnavailableError("backend down")

    def embed_query(self, text: str) -> list[float]:
        raise EmbeddingUnavailableError("backend down")


@pytest.fixture
def settings(database_url: str) -> Any:
    return source_settings(database_url)


@pytest.fixture
def seeded(settings: Any, session_factory: Any) -> Any:
    upstream = FakeUpstream()
    seed_fixture_data(settings, session_factory, upstream)
    return http_factory_for(settings, upstream)


def embed(
    settings: Any, session_factory: Any, http: Any, embedder: Any = None, **params: Any
) -> Any:
    return run_now(EmbeddingsAdapter(embedder), params, settings, session_factory, http)


def test_embeddings_job_is_idempotent(
    settings: Any, session_factory: Any, seeded: Any, db: Session
) -> None:
    first = embed(settings, session_factory, seeded)
    second = embed(settings, session_factory, seeded)

    chunks = db.scalar(select(func.count()).select_from(DocumentChunk))
    assert first.status == "succeeded" and first.records_inserted == chunks
    assert second.records_inserted == 0 and second.records_unchanged == chunks
    assert second.details["chunks_written"] == 0
    types = set(db.scalars(select(DocumentChunk.entity_type)))
    assert types == {"vulnerability", "kev", "attack_technique"}


def test_changed_record_is_rechunked_and_reembedded(
    settings: Any, session_factory: Any, seeded: Any, db: Session
) -> None:
    embed(settings, session_factory, seeded)
    with session_factory.begin() as session:
        session.execute(
            update(Vulnerability)
            .where(Vulnerability.cve_id == "CVE-2023-30861")
            .values(description="Changed description for the test.")
        )

    job = embed(settings, session_factory, seeded)

    assert job.details["chunks_written"] == 1
    assert job.records_inserted == 1  # only the rewritten chunk needed a new vector
    chunk = db.scalar(select(DocumentChunk).where(DocumentChunk.entity_id == "CVE-2023-30861"))
    assert chunk is not None and "Changed description" in chunk.content


def test_kev_only_document_disappears_once_record_exists(
    settings: Any, session_factory: Any, seeded: Any, db: Session
) -> None:
    embed(settings, session_factory, seeded)
    kev_docs = set(
        db.scalars(select(DocumentChunk.entity_id).where(DocumentChunk.entity_type == "kev"))
    )
    assert "CVE-2021-44228" not in kev_docs  # its CVE record is stored
    assert "CVE-2023-4966" in kev_docs


def test_switching_model_prunes_old_vectors(
    settings: Any, session_factory: Any, seeded: Any, db: Session
) -> None:
    embed(settings, session_factory, seeded)

    class OtherModel(HashingEmbedder):
        name = "hashing-other"

    embed(settings, session_factory, seeded, OtherModel())
    models = db.execute(
        select(EmbeddingModel.name, func.count(ChunkEmbedding.chunk_id))
        .outerjoin(ChunkEmbedding)
        .group_by(EmbeddingModel.name)
    ).all()
    assert dict(models)["hashing-other"] > 0 and dict(models)["hashing-v2"] == 0


def test_unavailable_embedder_fails_job_but_keeps_chunks(
    settings: Any, session_factory: Any, seeded: Any, db: Session
) -> None:
    job = embed(settings, session_factory, seeded, BrokenEmbedder())
    assert job.status == "failed" and job.records_failed > 0
    assert db.scalar(select(func.count()).select_from(DocumentChunk)) > 0


def test_retrieve_finds_relevant_evidence(
    settings: Any, session_factory: Any, seeded: Any, db: Session
) -> None:
    embed(settings, session_factory, seeded)
    embedder = HashingEmbedder()

    result = retrieve(db, "log4j jndi remote code execution", embedder, k=3)
    assert result.vector_used and result.mode == "hybrid"
    assert result.chunks[0].cve_id == "CVE-2021-44228"

    cookie = retrieve(
        db,
        "persistent session cookie",
        embedder,
        k=5,
        filters=RetrievalFilters(entity_types=["vulnerability"]),
    )
    assert cookie.chunks[0].cve_id == "CVE-2023-30861"

    kev_only = retrieve(db, "vulnerability", embedder, k=10, filters=RetrievalFilters(in_kev=True))
    assert kev_only.chunks and all(c.metadata["in_kev"] for c in kev_only.chunks)

    critical = retrieve(
        db, "apache", embedder, k=10, filters=RetrievalFilters(severity=["CRITICAL"])
    )
    assert {c.cve_id for c in critical.chunks} == {"CVE-2021-44228"}


def test_retrieve_falls_back_to_keyword(
    settings: Any, session_factory: Any, seeded: Any, db: Session
) -> None:
    embed(settings, session_factory, seeded)

    no_model = retrieve(db, "log4j", None)
    assert no_model.mode == "keyword" and not no_model.vector_used and no_model.chunks
    assert "disabled" in no_model.warnings[0]

    broken = retrieve(db, "log4j", BrokenEmbedder())
    assert broken.mode == "keyword" and "No embeddings stored" in broken.warnings[0]


@pytest.fixture
def client(settings: Any, session_factory: Any, seeded: Any) -> Iterator[TestClient]:
    embed(settings, session_factory, seeded)
    with TestClient(create_app(settings)) as test_client:
        yield test_client


def test_search_api(client: TestClient) -> None:
    body = client.get("/api/v1/search", params={"q": "log4j jndi", "k": 3}).json()

    assert body["vector_used"] is True and body["semantic_model"] is False
    assert body["embedding_model"] == "hashing/hashing-v2"
    assert any("lexical" in w for w in body["warnings"])
    assert body["results"][0]["cve_id"] == "CVE-2021-44228"
    ids = [(r["entity_type"], r["entity_id"]) for r in body["results"]]
    assert len(ids) == len(set(ids))  # one chunk per entity

    keyword = client.get("/api/v1/search", params={"q": "cookie", "mode": "keyword"}).json()
    assert keyword["mode"] == "keyword" and keyword["vector_used"] is False

    techniques = client.get(
        "/api/v1/search", params={"q": "command interpreter", "entity_type": "attack_technique"}
    ).json()
    assert techniques["results"][0]["entity_id"].startswith("T1059")

    assert client.get("/api/v1/search", params={"q": "x"}).status_code == 422
    assert client.get("/api/v1/search", params={"q": "ok", "k": 51}).status_code == 422
    ready = client.get("/health/ready").json()
    assert ready["checks"]["embeddings"]["status"] == "ok"
