"""Gemini provider and embedder, against mocked HTTP responses (no API key, no network).

The official SDK is exercised end to end: it builds the real request, and an
``httpx.MockTransport`` plays the Gemini API.
"""

from __future__ import annotations

import json
import logging
import math
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from app.core.gemini import Cooldown
from app.core.logging import redact
from app.llm.health import llm_probe
from app.llm.providers import (
    GeminiProvider,
    LLMTimeoutError,
    LLMUnavailableError,
    build_llm,
)
from app.main import create_app
from app.retrieval.embedders import EmbeddingUnavailableError, GeminiEmbedder, build_embedder
from tests.conftest import make_settings

FAKE_KEY = "test-only-gemini-key"  # not a real credential
MODEL = "gemini-test-flash"
EMBED_MODEL = "gemini-test-embedding"
# Marker planted in error bodies: it must never reach an exception message.
BODY_MARKER = "account-detail-from-error-body"

Handler = Callable[[httpx.Request], httpx.Response]


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _answer(text: str, finish: str = "STOP", **extra: Any) -> dict[str, Any]:
    return {
        "candidates": [
            {"content": {"role": "model", "parts": [{"text": text}]}, "finishReason": finish}
        ],
        **extra,
    }


def _error(code: int, status: str, details: list[dict[str, Any]] | None = None) -> httpx.Response:
    body = {"error": {"code": code, "status": status, "message": BODY_MARKER}}
    if details:
        body["error"]["details"] = details
    return httpx.Response(code, json=body)


def _provider(handler: Handler, *, clock: FakeClock | None = None, **kwargs: Any) -> GeminiProvider:
    return GeminiProvider(
        FAKE_KEY,
        MODEL,
        timeout_seconds=5,
        max_tokens=300,
        temperature=0.1,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        cooldown=Cooldown(clock or FakeClock()),
        **kwargs,
    )


# --- configuration ----------------------------------------------------------------------


def test_no_gemini_model_is_assumed() -> None:
    settings = make_settings(llm_provider="gemini", embedding_provider="gemini")
    assert settings.gemini_model is None
    assert settings.gemini_embedding_model is None
    assert settings.gemini_problem("llm") == (
        "Gemini is selected but GEMINI_API_KEY and GEMINI_MODEL not set"
    )
    configured = make_settings(gemini_api_key=FAKE_KEY, gemini_model=MODEL)
    assert configured.gemini_problem("llm") is None
    assert configured.gemini_problem("embedding") == (
        "Gemini is selected but GEMINI_EMBEDDING_MODEL not set"
    )


def test_blank_values_count_as_unset() -> None:
    settings = make_settings(gemini_api_key="  ", gemini_model="", gemini_thinking_budget="")
    assert settings.gemini_api_key is None
    assert settings.gemini_model is None
    assert settings.gemini_thinking_budget is None


def test_env_example_values_load(monkeypatch: pytest.MonkeyPatch) -> None:
    # The empty Gemini lines of .env.example (and of compose.yaml) must not break startup.
    for name in (
        "GEMINI_API_KEY",
        "GEMINI_MODEL",
        "GEMINI_EMBEDDING_MODEL",
        "GEMINI_THINKING_BUDGET",
    ):
        monkeypatch.setenv(name, "")
    settings = make_settings(llm_provider="gemini")
    assert settings.gemini_problem("llm") is not None


@pytest.mark.parametrize("model", ["../v1/files", "gemini flash", "Gemini-Pro", "a" * 120])
def test_model_codes_cannot_alter_the_request_path(model: str) -> None:
    with pytest.raises(ValueError, match="Gemini model code"):
        make_settings(gemini_model=model)


def test_key_is_masked_in_repr() -> None:
    settings = make_settings(gemini_api_key=FAKE_KEY)
    assert FAKE_KEY not in repr(settings)
    assert FAKE_KEY not in str(settings.model_dump())


def test_production_starts_without_a_gemini_key() -> None:
    settings = make_settings(
        environment="production",
        llm_provider="gemini",
        embedding_provider="gemini",
        admin_api_key="k" * 40,
        cors_origins=["https://app.example.org"],
    )
    assert build_llm(settings) is None
    assert build_embedder(settings) is None


def test_missing_key_disables_gemini_and_logs_no_secret(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING)
    assert build_llm(make_settings(llm_provider="gemini", gemini_model=MODEL)) is None
    assert "GEMINI_API_KEY" in caplog.text
    assert build_llm(make_settings(llm_provider="gemini", gemini_api_key=FAKE_KEY)) is None
    assert "GEMINI_MODEL" in caplog.text
    assert FAKE_KEY not in caplog.text


def test_configured_gemini_is_built() -> None:
    llm = build_llm(
        make_settings(
            llm_provider="gemini",
            gemini_api_key=FAKE_KEY,
            gemini_model=f"models/{MODEL}",
            gemini_thinking_budget=0,
        )
    )
    assert isinstance(llm, GeminiProvider)
    assert llm.model == MODEL
    assert llm.thinking_budget == 0


def test_readiness_explains_a_missing_key() -> None:
    app = create_app(make_settings(llm_provider="gemini", embedding_provider="gemini"))
    with TestClient(app):
        llm = llm_probe(app)
        assert llm.status == "degraded"
        assert "GEMINI_API_KEY" in (llm.detail or "")
        assert "evidence only" in (llm.detail or "")


# --- generation -------------------------------------------------------------------------


def test_request_shape_and_key_placement() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=_answer("Patch now [E1]."))

    result = _provider(handler, thinking_budget=0).generate("SYSTEM RULES", "QUESTION")
    assert result.text == "Patch now [E1]."
    assert (result.provider, result.model, result.truncated) == ("gemini", MODEL, False)

    request = seen[0]
    assert request.url.path.endswith(f"/models/{MODEL}:generateContent")
    assert request.headers["x-goog-api-key"] == FAKE_KEY
    assert FAKE_KEY not in str(request.url)
    body = json.loads(request.content)
    assert body["systemInstruction"]["parts"][0]["text"] == "SYSTEM RULES"
    assert body["contents"][0]["parts"][0]["text"] == "QUESTION"
    config = body["generationConfig"]
    assert config["temperature"] == 0.1
    assert config["maxOutputTokens"] == 300
    assert config["candidateCount"] == 1
    # The SDK sends the proto field name; the API accepts either JSON spelling.
    assert config["thinkingConfig"] in ({"thinkingBudget": 0}, {"thinking_budget": 0})
    assert "tools" not in body  # the model gets no tools
    # Google's default safety settings are never loosened.
    assert "safetySettings" not in body


def test_thought_parts_are_not_part_of_the_answer() -> None:
    payload = {
        "candidates": [
            {
                "content": {
                    "role": "model",
                    "parts": [
                        {"text": "internal reasoning", "thought": True},
                        {"text": "Answer [E2]."},
                    ],
                },
                "finishReason": "STOP",
            }
        ]
    }
    result = _provider(lambda r: httpx.Response(200, json=payload)).generate("s", "u")
    assert result.text == "Answer [E2]."


def test_length_limit_is_reported() -> None:
    result = _provider(
        lambda r: httpx.Response(200, json=_answer("Partial", "MAX_TOKENS"))
    ).generate("s", "u")
    assert result.truncated is True
    with pytest.raises(LLMUnavailableError, match="LLM_MAX_TOKENS"):
        _provider(lambda r: httpx.Response(200, json=_answer("", "MAX_TOKENS"))).generate("s", "u")


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (_answer("partial unsafe text", "SAFETY"), r"stopped the answer \(SAFETY\)"),
        (_answer("quoted text", "RECITATION"), r"stopped the answer \(RECITATION\)"),
        ({"promptFeedback": {"blockReason": "PROHIBITED_CONTENT"}}, "blocked the request"),
        ({"candidates": []}, "no answer"),
        (_answer("   "), "empty answer"),
    ],
)
def test_blocked_or_empty_answers_are_never_shown(payload: dict[str, Any], message: str) -> None:
    with pytest.raises(LLMUnavailableError, match=message) as info:
        _provider(lambda r: httpx.Response(200, json=payload)).generate("s", "u")
    assert "unsafe text" not in str(info.value)


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (_error(400, "INVALID_ARGUMENT", [
            {"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": "API_KEY_INVALID"}
        ]), "rejected the API key"),
        (_error(403, "PERMISSION_DENIED"), "rejected the API key"),
        (_error(404, "NOT_FOUND"), "python -m app.llm.gemini_models"),
        (_error(400, "FAILED_PRECONDITION"), r"rejected the request \(HTTP 400"),
        (_error(503, "UNAVAILABLE"), r"API error \(HTTP 503 UNAVAILABLE\)"),
    ],
)  # fmt: skip
def test_api_errors_are_mapped_without_echoing_the_body(
    response: httpx.Response, message: str, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    with pytest.raises(LLMUnavailableError, match=message) as info:
        _provider(lambda r: response).generate("s", "u")
    assert BODY_MARKER not in str(info.value)
    assert FAKE_KEY not in str(info.value)
    assert FAKE_KEY not in caplog.text


def test_rate_limit_trips_a_cooldown_instead_of_hammering_the_api() -> None:
    calls = 0
    clock = FakeClock()

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return _error(429, "RESOURCE_EXHAUSTED", [
                {"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": "37s"}
            ])  # fmt: skip
        return httpx.Response(200, json=_answer("Recovered [E1]."))

    llm = _provider(handler, clock=clock)
    with pytest.raises(LLMUnavailableError, match="retry in about 37 s"):
        llm.generate("s", "u")
    with pytest.raises(LLMUnavailableError, match="not retrying for about 37 s"):
        llm.generate("s", "u")
    assert calls == 1  # the second call never reached the API

    clock.now += 38
    assert llm.generate("s", "u").text == "Recovered [E1]."
    assert calls == 2


def test_daily_quota_exhaustion_has_a_long_cooldown() -> None:
    clock = FakeClock()
    quota = _error(429, "RESOURCE_EXHAUSTED", [
        {
            "@type": "type.googleapis.com/google.rpc.QuotaFailure",
            "violations": [{"quotaId": "GenerateRequestsPerDayPerProjectPerModel-FreeTier"}],
        },
        {"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": "20s"},
    ])  # fmt: skip
    llm = _provider(lambda r: quota, clock=clock)
    with pytest.raises(LLMUnavailableError, match="daily quota"):
        llm.generate("s", "u")
    clock.now += 60
    assert llm.cooldown.remaining() > 500


def test_timeouts_and_network_errors() -> None:
    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route", request=request)

    with pytest.raises(LLMTimeoutError, match="in time"):
        _provider(timeout).generate("s", "u")
    with pytest.raises(LLMUnavailableError, match=r"not reachable \(ConnectError\)"):
        _provider(down).generate("s", "u")


def test_unparseable_response_is_contained() -> None:
    with pytest.raises(LLMUnavailableError, match="unexpected response"):
        _provider(lambda r: httpx.Response(200, content=b"<html>proxy page</html>")).generate(
            "s", "u"
        )


def test_readiness_reports_a_rate_limited_provider() -> None:
    clock = FakeClock()
    llm = _provider(lambda r: _error(429, "RESOURCE_EXHAUSTED"), clock=clock)

    class State:
        pass

    class App:
        state = State()

    App.state.llm = llm  # type: ignore[attr-defined]
    assert llm_probe(App).status == "ok"
    with pytest.raises(LLMUnavailableError):
        llm.generate("s", "u")
    check = llm_probe(App)
    assert check.status == "degraded"
    assert "rate limited" in (check.detail or "")


# --- embeddings -------------------------------------------------------------------------


def _vectors(count: int, dimension: int = 768, value: float = 0.5) -> dict[str, Any]:
    return {"embeddings": [{"values": [value] * dimension} for _ in range(count)]}


def _embedder(handler: Handler, **kwargs: Any) -> GeminiEmbedder:
    kwargs.setdefault("cooldown", Cooldown(FakeClock()))
    return GeminiEmbedder(
        FAKE_KEY,
        EMBED_MODEL,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        **kwargs,
    )


def test_embeddings_request_768_dimensions_and_are_normalised() -> None:
    bodies: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-goog-api-key"] == FAKE_KEY
        body = json.loads(request.content)
        bodies.append(body)
        return httpx.Response(200, json=_vectors(len(body["requests"])))

    embedder = _embedder(handler)
    assert (embedder.provider, embedder.name, embedder.dimension) == ("gemini", EMBED_MODEL, 768)
    assert embedder.semantic is True

    docs = embedder.embed_documents(["chunk one", "chunk two"])
    query = embedder.embed_query("which CVE?")
    assert len(docs) == 2
    assert all(len(v) == 768 for v in [*docs, query])
    assert math.isclose(math.sqrt(sum(x * x for x in query)), 1.0)

    doc_request, query_request = bodies[0]["requests"][0], bodies[1]["requests"][0]
    assert doc_request["taskType"] == "RETRIEVAL_DOCUMENT"
    assert query_request["taskType"] == "RETRIEVAL_QUERY"
    assert doc_request["outputDimensionality"] == 768
    assert doc_request["model"] == f"models/{EMBED_MODEL}"


def test_large_inputs_are_split_into_api_sized_batches() -> None:
    sizes: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        count = len(json.loads(request.content)["requests"])
        sizes.append(count)
        return httpx.Response(200, json=_vectors(count))

    assert len(_embedder(handler).embed_documents(["t"] * 250)) == 250
    assert sizes == [100, 100, 50]


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (_vectors(1, dimension=3072), "3072 dimensions"),
        (_vectors(2), "unexpected embedding payload"),
        (_vectors(1, value=0.0), "all-zero"),
    ],
)
def test_bad_embedding_payloads_are_rejected(payload: dict[str, Any], message: str) -> None:
    with pytest.raises(EmbeddingUnavailableError, match=message):
        _embedder(lambda r: httpx.Response(200, json=payload)).embed_query("q")


def test_indexing_waits_out_a_short_rate_limit() -> None:
    calls, slept = 0, []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return _error(429, "RESOURCE_EXHAUSTED", [
                {"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": "12s"}
            ])  # fmt: skip
        return httpx.Response(200, json=_vectors(len(json.loads(request.content)["requests"])))

    vectors = _embedder(handler, sleep=slept.append).embed_documents(["a", "b"])
    assert len(vectors) == 2
    assert slept == [12.0]


def test_indexing_gives_up_on_quota_and_long_waits() -> None:
    slept: list[float] = []
    quota = _error(429, "RESOURCE_EXHAUSTED", [
        {
            "@type": "type.googleapis.com/google.rpc.QuotaFailure",
            "violations": [{"quotaId": "EmbedContentRequestsPerDayPerProject-FreeTier"}],
        }
    ])  # fmt: skip
    with pytest.raises(EmbeddingUnavailableError, match="daily quota"):
        _embedder(lambda r: quota, sleep=slept.append).embed_documents(["a"])
    long_wait = _error(429, "RESOURCE_EXHAUSTED", [
        {"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": "3600s"}
    ])  # fmt: skip
    with pytest.raises(EmbeddingUnavailableError, match="rate limit"):
        _embedder(lambda r: long_wait, sleep=slept.append).embed_documents(["a"])
    assert slept == []


def test_queries_never_wait_for_a_rate_limit() -> None:
    slept: list[float] = []
    limited = _error(429, "RESOURCE_EXHAUSTED", [
        {"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": "5s"}
    ])  # fmt: skip
    embedder = _embedder(lambda r: limited, sleep=slept.append)
    with pytest.raises(EmbeddingUnavailableError, match="rate limit"):
        embedder.embed_query("q")
    with pytest.raises(EmbeddingUnavailableError, match="not retrying"):
        embedder.embed_query("q")
    assert slept == []


def test_embedding_errors_do_not_echo_the_body() -> None:
    with pytest.raises(EmbeddingUnavailableError) as info:
        _embedder(lambda r: _error(500, "INTERNAL")).embed_query("q")
    assert BODY_MARKER not in str(info.value)
    assert "HTTP 500 INTERNAL" in str(info.value)


def test_gemini_embedder_is_built_only_when_configured() -> None:
    assert (
        build_embedder(make_settings(embedding_provider="gemini", gemini_api_key=FAKE_KEY)) is None
    )
    embedder = build_embedder(
        make_settings(
            embedding_provider="gemini",
            gemini_api_key=FAKE_KEY,
            gemini_embedding_model=EMBED_MODEL,
        )
    )
    assert isinstance(embedder, GeminiEmbedder)


# --- logging ----------------------------------------------------------------------------


def test_google_api_keys_are_redacted_from_logs() -> None:
    key = "AIza" + "Q" * 35  # the shape of a Google API key; not a real one
    assert key not in redact(f"failed calling model with {key}")
    assert key not in redact(f"GET https://example.test/v1/models?key={key}&alt=json")
    assert "secretvalue" not in redact("x-goog-api-key: secretvalue")
