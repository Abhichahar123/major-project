"""Embedding providers.

* ``HashingEmbedder``: deterministic feature hashing of words, bigrams and security
  identifiers into 768 dimensions. No model download and fully reproducible, but
  **lexical, not semantic**: it only matches shared terms. Used for development, tests
  and as a baseline in the evaluation.
* ``OllamaEmbedder``: real semantic embeddings from a local Ollama server
  (e.g. ``nomic-embed-text``, 768 dimensions, about 270 MB to download with
  ``ollama pull nomic-embed-text``).
* ``GeminiEmbedder``: semantic embeddings from Google's Gemini API, requested at 768
  dimensions (``output_dimensionality``) so they fit the existing column without a
  migration. Chunk text and queries are sent to Google.

The vector column has a fixed dimension (``EMBEDDING_DIMENSION``); a model returning a
different size is rejected rather than silently truncated.
"""

from __future__ import annotations

import hashlib
import itertools
import logging
import math
import re
import time
from collections import Counter
from collections.abc import Callable
from typing import Literal, Protocol

import httpx
from google.genai import errors as genai_errors
from google.genai import types as genai_types

from app.core.config import Settings
from app.core.gemini import Cooldown, GeminiFailure, classify_error, make_client
from app.db.models import EMBEDDING_DIMENSION

logger = logging.getLogger(__name__)


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


class GeminiEmbedder:
    provider = "gemini"
    semantic = True
    # batchEmbedContents accepts at most 100 texts per request.
    MAX_BATCH = 100
    # Indexing waits out short per-minute rate limits; queries never wait.
    MAX_RATE_LIMIT_WAITS = 3
    MAX_WAIT_SECONDS = 65.0

    def __init__(
        self,
        api_key: str,
        model: str,
        *,
        timeout_seconds: float = 60.0,
        dimension: int = EMBEDDING_DIMENSION,
        http_client: httpx.Client | None = None,
        cooldown: Cooldown | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.name = model.removeprefix("models/")
        self.dimension = dimension
        self._client = make_client(
            api_key, timeout_seconds=timeout_seconds, http_client=http_client
        )
        self.cooldown = cooldown or Cooldown()
        self._sleep = sleep

    def _call(
        self, texts: list[str], task: Literal["RETRIEVAL_DOCUMENT", "RETRIEVAL_QUERY"]
    ) -> list[list[float]]:
        if (wait := self.cooldown.remaining()) > 0:
            raise EmbeddingUnavailableError(
                f"Gemini rate limit or quota reached; not retrying for about {round(wait)} s."
            )
        config = genai_types.EmbedContentConfig(
            task_type=task, output_dimensionality=self.dimension
        )
        try:
            response = self._client.models.embed_content(
                model=self.name,
                contents=texts,
                config=config,
            )
        except (genai_errors.APIError, httpx.HTTPError) as exc:
            failure = classify_error(exc, self.name) or GeminiFailure("server", "Gemini API error")
            self.cooldown.trip(failure)
            logger.warning(
                "Gemini embedding failed",
                extra={"failure": failure.kind, "error_type": type(exc).__name__},
            )
            raise _GeminiEmbeddingError(failure) from exc
        except Exception as exc:  # e.g. a response the SDK cannot parse
            raise EmbeddingUnavailableError("Gemini returned an unexpected response.") from exc
        vectors = [list(e.values or []) for e in response.embeddings or []]
        if len(vectors) != len(texts):
            raise EmbeddingUnavailableError("Gemini returned an unexpected embedding payload.")
        result = []
        for vector in vectors:
            if len(vector) != self.dimension:
                raise EmbeddingUnavailableError(
                    f"model {self.name!r} returned {len(vector)} dimensions instead of the "
                    f"{self.dimension} the database stores."
                )
            # Reduced-dimension Gemini embeddings are not unit length; normalise them.
            norm = math.sqrt(sum(x * x for x in vector))
            if norm == 0:
                raise EmbeddingUnavailableError("Gemini returned an all-zero embedding.")
            result.append([float(x) / norm for x in vector])
        return result

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        vectors: list[list[float]] = []
        for start in range(0, len(texts), self.MAX_BATCH):
            batch = texts[start : start + self.MAX_BATCH]
            waits = 0
            while True:
                try:
                    vectors.extend(self._call(batch, "RETRIEVAL_DOCUMENT"))
                    break
                except _GeminiEmbeddingError as exc:
                    delay = exc.failure.retry_after or 0.0
                    if (
                        exc.failure.kind != "rate_limited"
                        or waits >= self.MAX_RATE_LIMIT_WAITS
                        or delay > self.MAX_WAIT_SECONDS
                    ):
                        raise
                    # A per-minute limit while indexing: wait it out (bounded), then retry.
                    waits += 1
                    self._sleep(max(delay, 1.0))
                    self.cooldown.reset()
        return vectors

    def embed_query(self, text: str) -> list[float]:
        return self._call([text], "RETRIEVAL_QUERY")[0]


class _GeminiEmbeddingError(EmbeddingUnavailableError):
    def __init__(self, failure: GeminiFailure) -> None:
        super().__init__(failure.message[:1].upper() + failure.message[1:] + ".")
        self.failure = failure


def build_embedder(settings: Settings) -> Embedder | None:
    """Return the configured embedder, or None when semantic retrieval is disabled."""
    if settings.embedding_provider == "hashing":
        return HashingEmbedder()
    if settings.embedding_provider == "ollama":
        return OllamaEmbedder(
            settings.ollama_base_url, settings.embedding_model, settings.embedding_timeout_seconds
        )
    if settings.embedding_provider == "gemini":
        key, model = settings.gemini_api_key, settings.gemini_embedding_model
        if key is None or model is None:
            # Never fall back to another embedder silently: its vectors would replace the
            # Gemini ones. Search runs keyword-only and /health/ready says why.
            logger.warning("%s; search is keyword-only", settings.gemini_problem("embedding"))
            return None
        return GeminiEmbedder(
            key.get_secret_value(), model, timeout_seconds=settings.embedding_timeout_seconds
        )
    return None
