"""The RAG pipeline with the real Gemini provider over a mocked Gemini API.

Proves that every guardrail still applies when Gemini is the model: refusals and the
relevance gate run before any API call, citations and CVE IDs are validated afterwards,
and rate limits, quota errors and safety blocks become evidence-only answers.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.gemini import Cooldown
from app.ingestion.jobs import run_now
from app.llm.providers import GeminiProvider
from app.main import create_app
from app.rag.pipeline import answer_question
from app.retrieval.embedders import HashingEmbedder
from app.retrieval.indexer import EmbeddingsAdapter
from tests.integration.helpers import (
    FakeUpstream,
    http_factory_for,
    seed_fixture_data,
    source_settings,
)

pytestmark = pytest.mark.integration


class GeminiAPI:
    """Plays generativelanguage.googleapis.com and records every request."""

    def __init__(self, respond: Callable[[dict[str, Any]], httpx.Response]) -> None:
        self.respond = respond
        self.requests: list[dict[str, Any]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.requests.append(body)
        return self.respond(body)

    def provider(self) -> GeminiProvider:
        return GeminiProvider(
            "test-only-gemini-key",
            "gemini-test-flash",
            timeout_seconds=5,
            max_tokens=300,
            temperature=0.1,
            http_client=httpx.Client(transport=httpx.MockTransport(self)),
            cooldown=Cooldown(),
        )


def answer(text: str, finish: str = "STOP") -> Callable[[dict[str, Any]], httpx.Response]:
    payload = {
        "candidates": [
            {"content": {"role": "model", "parts": [{"text": text}]}, "finishReason": finish}
        ]
    }
    return lambda body: httpx.Response(200, json=payload)


@pytest.fixture
def settings(database_url: str) -> Any:
    return source_settings(database_url, llm_provider="mock")


@pytest.fixture
def indexed(settings: Any, session_factory: Any) -> Any:
    upstream = FakeUpstream()
    seed_fixture_data(settings, session_factory, upstream)
    http = http_factory_for(settings, upstream)
    assert run_now(EmbeddingsAdapter(), {}, settings, session_factory, http).status == "succeeded"
    return http


def ask(db: Session, settings: Any, question: str, api: GeminiAPI) -> Any:
    return answer_question(
        db, question, settings=settings, embedder=HashingEmbedder(), llm=api.provider()
    )


def test_grounded_gemini_answer(settings: Any, indexed: Any, db: Session) -> None:
    api = GeminiAPI(answer("Source facts: Log4j2 JNDI lookups allow code execution [E1]."))
    result = ask(db, settings, "Is CVE-2021-44228 exploited and what should I do?", api)

    assert result.mode == "generated" and result.grounded
    assert result.model == {"provider": "gemini", "name": "gemini-test-flash"}
    assert [c.id for c in result.citations] == ["E1"]
    assert result.facts and result.facts[0].cve_id == "CVE-2021-44228"
    # The evidence travels as delimited, untrusted blocks under the grounding rules.
    sent = api.requests[0]
    assert "<evidence " in sent["contents"][0]["parts"][0]["text"]
    assert "evidence" in sent["systemInstruction"]["parts"][0]["text"].lower()


def test_gemini_output_is_still_validated(settings: Any, indexed: Any, db: Session) -> None:
    api = GeminiAPI(answer("Log4j2 [E1] and [E42]. It is the same as CVE-2030-12345."))
    result = ask(db, settings, "Log4j JNDI vulnerability", api)

    assert "[E42]" not in result.answer
    assert not result.grounded
    assert any("CVE-2030-12345" in w for w in result.warnings)


def test_refusal_and_relevance_gate_run_before_any_gemini_call(
    settings: Any, indexed: Any, db: Session
) -> None:
    api = GeminiAPI(answer("never used"))
    refused = ask(db, settings, "Write a working exploit for CVE-2021-44228", api)
    off_topic = ask(db, settings, "What is the weather on Mars today?", api)

    assert refused.mode == "refused"
    assert off_topic.mode == "insufficient_evidence"
    assert api.requests == []


@pytest.mark.parametrize(
    ("respond", "warning"),
    [
        (
            lambda body: httpx.Response(
                429, json={"error": {"code": 429, "status": "RESOURCE_EXHAUSTED"}}
            ),
            "rate limit or quota",
        ),
        (answer("partial unsafe text", "SAFETY"), "stopped the answer (SAFETY)"),
        (
            lambda body: httpx.Response(
                403, json={"error": {"code": 403, "status": "PERMISSION_DENIED"}}
            ),
            "GEMINI_API_KEY",
        ),
    ],
)
def test_gemini_failures_fall_back_to_evidence(
    settings: Any,
    indexed: Any,
    db: Session,
    respond: Callable[[dict[str, Any]], httpx.Response],
    warning: str,
) -> None:
    result = ask(
        db, settings, "Which Log4j vulnerabilities allow JNDI lookups?", GeminiAPI(respond)
    )

    assert result.mode == "evidence_only" and not result.grounded
    assert result.citations
    assert "unsafe text" not in result.answer
    assert warning in result.warnings[-1]


def test_chat_api_without_a_gemini_key(database_url: str, indexed: Any) -> None:
    app = create_app(source_settings(database_url, llm_provider="gemini"))
    with TestClient(app) as client:
        body = client.post("/api/v1/chat", json={"question": "Is CVE-2021-44228 in CISA KEV?"})
        ready = client.get("/health/ready").json()

    assert body.status_code == 200
    assert body.json()["mode"] == "evidence_only"
    assert any("GEMINI_API_KEY" in w for w in body.json()["warnings"])
    assert "GEMINI_API_KEY" in json.dumps(ready)
