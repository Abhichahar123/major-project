"""Unit tests for chunking and embedders (no database, no model downloads)."""

from __future__ import annotations

import json
import math

import httpx
import pytest

from app.retrieval.documents import Document, _split, chunk_document
from app.retrieval.embedders import EmbeddingUnavailableError, HashingEmbedder, OllamaEmbedder


def cosine(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b, strict=True))


def test_short_text_is_one_chunk_with_header() -> None:
    doc = Document(
        "vulnerability",
        "CVE-2021-44228",
        "CVE-2021-44228",
        "CVE-2021-44228: Log4Shell",
        "Short body.",
        "CVE Program record",
        None,
    )
    [(content, digest)] = chunk_document(doc)
    assert content == "CVE-2021-44228: Log4Shell\nShort body."
    assert len(digest) == 64


def test_long_text_splits_on_boundaries_with_overlap() -> None:
    sentence = "This sentence describes part of a long vulnerability description. "
    text = sentence * 60
    chunks = _split(text, limit=500, overlap=80)

    assert len(chunks) > 1
    assert all(len(c) <= 500 for c in chunks)
    assert all(c.endswith(".") for c in chunks[:-1])  # cut at sentence ends
    assert chunks[0][-40:] in chunks[0] and any(chunks[0][-30:] in c for c in chunks[1:2])


def test_every_chunk_keeps_the_identifier() -> None:
    doc = Document(
        "vulnerability",
        "CVE-2024-0001",
        "CVE-2024-0001",
        "CVE-2024-0001: title",
        "word " * 2000,
        "src",
        None,
    )
    chunks = chunk_document(doc)
    assert len(chunks) > 2
    assert all(c.startswith("CVE-2024-0001: title\n") for c, _ in chunks)
    assert all(len(c) <= 1200 for c, _ in chunks)


def test_hashing_embedder_is_deterministic_and_normalized() -> None:
    embedder = HashingEmbedder()
    a = embedder.embed_query("Apache Log4j2 JNDI remote code execution")
    b = embedder.embed_query("Apache Log4j2 JNDI remote code execution")

    assert a == b and len(a) == 768
    assert math.isclose(math.sqrt(sum(x * x for x in a)), 1.0, rel_tol=1e-9)
    assert embedder.semantic is False


def test_hashing_embedder_prefers_shared_terms_and_identifiers() -> None:
    e = HashingEmbedder()
    query = e.embed_query("log4j jndi lookup")
    related = e.embed_documents(["CVE-2021-44228: Apache Log4j2 JNDI lookup flaw"])[0]
    unrelated = e.embed_documents(["Router firmware buffer overflow in DHCP"])[0]
    assert cosine(query, related) > cosine(query, unrelated)

    by_id = e.embed_query("CVE-2021-44228")
    assert cosine(by_id, related) > cosine(by_id, unrelated) + 0.1


def test_hashing_embedder_handles_empty_text() -> None:
    vector = HashingEmbedder().embed_query("")
    assert math.isclose(sum(v * v for v in vector), 1.0)


def _ollama(handler) -> OllamaEmbedder:  # type: ignore[no-untyped-def]
    return OllamaEmbedder(
        "http://ollama.test", "nomic-embed-text", transport=httpx.MockTransport(handler)
    )


def test_ollama_embedder_uses_task_prefixes() -> None:
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append(body)
        return httpx.Response(200, json={"embeddings": [[0.1] * 768 for _ in body["input"]]})

    embedder = _ollama(handler)
    assert len(embedder.embed_documents(["a", "b"])) == 2
    embedder.embed_query("q")
    assert seen[0]["input"] == ["search_document: a", "search_document: b"]
    assert seen[1]["input"] == ["search_query: q"]
    assert seen[0]["model"] == "nomic-embed-text"


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (httpx.Response(404, json={"error": "model not found"}), "ollama pull"),
        (httpx.Response(200, json={"embeddings": [[0.1] * 384]}), "384 dimensions"),
        (httpx.Response(500), "HTTP 500"),
        (httpx.Response(200, json={"unexpected": True}), "unexpected"),
    ],
)
def test_ollama_errors_are_explained(response: httpx.Response, message: str) -> None:
    with pytest.raises(EmbeddingUnavailableError, match=message):
        _ollama(lambda request: response).embed_query("q")


def test_ollama_unreachable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    with pytest.raises(EmbeddingUnavailableError, match="ollama serve"):
        _ollama(handler).embed_query("q")
