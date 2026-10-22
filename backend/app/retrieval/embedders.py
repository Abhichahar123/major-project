"""Embedding providers.

* ``HashingEmbedder``: deterministic feature hashing of words, bigrams and security
  identifiers into 768 dimensions. No model download and fully reproducible, but
  **lexical, not semantic**: it only matches shared terms. Used for development, tests
  and as a baseline in the evaluation.
* ``OllamaEmbedder``: real semantic embeddings from a local Ollama server
  (e.g. ``nomic-embed-text``, 768 dimensions, about 270 MB to download with
  ``ollama pull nomic-embed-text``).

The vector column has a fixed dimension (``EMBEDDING_DIMENSION``); a model returning a
different size is rejected rather than silently truncated.
"""

from __future__ import annotations

import hashlib
import itertools
import math
import re
from collections import Counter
from typing import Protocol

import httpx

from app.core.config import Settings
from app.db.models import EMBEDDING_DIMENSION


class EmbeddingUnavailableError(RuntimeError):
    """The embedding backend is not configured or not reachable."""


class Embedder(Protocol):
    provider: str
    name: str
    dimension: int
    semantic: bool

    def embed_documents(self, texts: list[str]) -> list[list[float]]: ...

    def embed_query(self, text: str) -> list[float]: ...


_IDENTIFIER = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|CWE-\d+|CAPEC-\d+|T\d{4}(?:\.\d{3})?)\b", re.I)
_WORD = re.compile(r"[a-z0-9][a-z0-9+#._-]*[a-z0-9]|[a-z0-9]")
_VERSION_SUFFIX = re.compile(r"(?<=[a-z])[0-9]+$")
_STOPWORDS = frozenset(
    {
        "a", "an", "and", "are", "as", "at", "be", "by", "can", "could", "for", "from",
        "has", "have", "in", "is", "it", "its", "may", "might", "of", "on", "or", "that",
        "the", "this", "to", "via", "was", "were", "which", "with",
    }
)  # fmt: skip


def _tokens(text: str) -> list[str]:
    identifiers = [m.upper() for m in _IDENTIFIER.findall(text)]
    words = [w for w in _WORD.findall(text.lower()) if w not in _STOPWORDS and len(w) > 1]
    # "log4j2" also counts as "log4j", "openssl3" as "openssl": product names often carry a
    # major version suffix that queries omit.
    variants = [v for w in words if (v := _VERSION_SUFFIX.sub("", w)) != w and len(v) >= 3]
    bigrams = [f"{a} {b}" for a, b in itertools.pairwise(words)]
    # Identifiers are repeated so an exact CVE/CWE/technique match dominates the score.
    return identifiers * 3 + words + variants + bigrams


class HashingEmbedder:
    provider = "hashing"
    name = "hashing-v2"  # bump whenever tokenization changes: vectors are not comparable
    semantic = False

    def __init__(self, dimension: int = EMBEDDING_DIMENSION) -> None:
        self.dimension = dimension

    def _embed(self, text: str) -> list[float]:
        vector = [0.0] * self.dimension
        for token, count in Counter(_tokens(text)).items():
            digest = hashlib.blake2b(token.encode(), digest_size=8).digest()
            index = int.from_bytes(digest[:4], "little") % self.dimension
            sign = 1.0 if digest[4] & 1 else -1.0
            vector[index] += sign * (1.0 + math.log(count))
        norm = math.sqrt(sum(v * v for v in vector))
        if norm == 0:
            vector[0] = 1.0  # empty text: a fixed unit vector keeps cosine distance defined
            return vector
        return [v / norm for v in vector]

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [self._embed(t) for t in texts]

    def embed_query(self, text: str) -> list[float]:
        return self._embed(text)


class OllamaEmbedder:
    provider = "ollama"
    semantic = True

    def __init__(
        self,
        base_url: str,
        model: str,
        timeout_seconds: float = 60.0,
        dimension: int = EMBEDDING_DIMENSION,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.name = model
        self.dimension = dimension
        self._client = httpx.Client(base_url=base_url, timeout=timeout_seconds, transport=transport)
        # nomic-embed-text is trained with task prefixes; other models get raw text.
        nomic = "nomic" in model.lower()
        self._doc_prefix = "search_document: " if nomic else ""
        self._query_prefix = "search_query: " if nomic else ""

    def _embed(self, texts: list[str]) -> list[list[float]]:
        try:
            response = self._client.post("/api/embed", json={"model": self.name, "input": texts})
        except httpx.HTTPError as exc:
            raise EmbeddingUnavailableError(
                f"Ollama is not reachable ({type(exc).__name__}); is `ollama serve` running?"
            ) from exc
        if response.status_code == 404:
            raise EmbeddingUnavailableError(
                f"Ollama model {self.name!r} is not available; run `ollama pull {self.name}`"
            )
        if response.status_code >= 400:
            raise EmbeddingUnavailableError(f"Ollama returned HTTP {response.status_code}")
        vectors = response.json().get("embeddings")
        if not isinstance(vectors, list) or len(vectors) != len(texts):
            raise EmbeddingUnavailableError("Ollama returned an unexpected embedding payload")
        for vector in vectors:
            if len(vector) != self.dimension:
                raise EmbeddingUnavailableError(
                    f"model {self.name!r} returns {len(vector)} dimensions; the database "
                    f"stores {self.dimension}. Choose a {self.dimension}-d model."
                )
        return [[float(x) for x in v] for v in vectors]

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return self._embed([self._doc_prefix + t for t in texts])

    def embed_query(self, text: str) -> list[float]:
        return self._embed([self._query_prefix + text])[0]


def build_embedder(settings: Settings) -> Embedder | None:
    """Return the configured embedder, or None when semantic retrieval is disabled."""
    if settings.embedding_provider == "hashing":
        return HashingEmbedder()
    if settings.embedding_provider == "ollama":
        return OllamaEmbedder(
            settings.ollama_base_url, settings.embedding_model, settings.embedding_timeout_seconds
        )
    return None
