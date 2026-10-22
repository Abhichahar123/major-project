"""LLM providers behind one small interface.

* ``OllamaProvider``: local inference through Ollama's ``/api/chat`` (primary option).
* ``OpenAICompatibleProvider``: any ``/chat/completions`` endpoint; only built when
  explicitly configured, because evidence and questions are sent to that third party.
* ``MockProvider``: deterministic, network-free answers for automated tests.

Providers raise ``LLMUnavailableError`` (not running, model missing, HTTP error) or
``LLMTimeoutError``; the RAG pipeline turns both into an evidence-only answer.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Protocol

import httpx

from app.core.config import Settings


class LLMUnavailableError(RuntimeError):
    pass


class LLMTimeoutError(LLMUnavailableError):
    pass


@dataclass
class LLMResult:
    text: str
    provider: str
    model: str
    latency_ms: float
    truncated: bool = False


class LLMProvider(Protocol):
    provider: str
    model: str

    def generate(self, system: str, user: str) -> LLMResult: ...


class OllamaProvider:
    provider = "ollama"

    def __init__(
        self,
        base_url: str,
        model: str,
        *,
        timeout_seconds: float,
        max_tokens: int,
        temperature: float,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self._client = httpx.Client(base_url=base_url, timeout=timeout_seconds, transport=transport)

    def generate(self, system: str, user: str) -> LLMResult:
        started = time.perf_counter()
        try:
            response = self._client.post(
                "/api/chat",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "stream": False,
                    "options": {"temperature": self.temperature, "num_predict": self.max_tokens},
                },
            )
        except httpx.TimeoutException as exc:
            raise LLMTimeoutError("the local model did not answer in time") from exc
        except httpx.HTTPError as exc:
            raise LLMUnavailableError(
                f"Ollama is not reachable ({type(exc).__name__}); start it with `ollama serve`"
            ) from exc
        if response.status_code == 404:
            raise LLMUnavailableError(
                f"model {self.model!r} not found; run `ollama pull {self.model}`"
            )
        if response.status_code >= 400:
            raise LLMUnavailableError(f"Ollama returned HTTP {response.status_code}")
        data = response.json()
        text = ((data.get("message") or {}).get("content") or "").strip()
        if not text:
            raise LLMUnavailableError("the model returned an empty answer")
        return LLMResult(
            text=text,
            provider=self.provider,
            model=self.model,
            latency_ms=round((time.perf_counter() - started) * 1000, 1),
            truncated=data.get("done_reason") == "length",
        )

    def ping(self) -> tuple[bool, str]:
        try:
            response = self._client.get("/api/tags", timeout=2.0)
            models = {m.get("name") for m in response.json().get("models", [])}
        except (httpx.HTTPError, ValueError):
            return False, "Ollama not reachable"
        if self.model not in models and f"{self.model}:latest" not in models:
            return False, f"model {self.model} not pulled"
        return True, f"ollama/{self.model}"


class OpenAICompatibleProvider:
    provider = "openai_compatible"

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        *,
        timeout_seconds: float,
        max_tokens: int,
        temperature: float,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"),
            timeout=timeout_seconds,
            headers={"Authorization": f"Bearer {api_key}"},
            transport=transport,
        )

    def generate(self, system: str, user: str) -> LLMResult:
        started = time.perf_counter()
        try:
            response = self._client.post(
                "/chat/completions",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "max_tokens": self.max_tokens,
                    "temperature": self.temperature,
                },
            )
        except httpx.TimeoutException as exc:
            raise LLMTimeoutError("the hosted model did not answer in time") from exc
        except httpx.HTTPError as exc:
            raise LLMUnavailableError(f"hosted LLM not reachable ({type(exc).__name__})") from exc
        if response.status_code >= 400:
            # Never echo the response body: it can contain account details.
            raise LLMUnavailableError(f"hosted LLM returned HTTP {response.status_code}")
        choice = (response.json().get("choices") or [{}])[0]
        text = ((choice.get("message") or {}).get("content") or "").strip()
        if not text:
            raise LLMUnavailableError("the hosted model returned an empty answer")
        return LLMResult(
            text=text,
            provider=self.provider,
            model=self.model,
            latency_ms=round((time.perf_counter() - started) * 1000, 1),
            truncated=choice.get("finish_reason") == "length",
        )


_EVIDENCE_ID = re.compile(r'<evidence id="(E\d+)"[^>]*\btitle="([^"]*)"')


class MockProvider:
    """Deterministic stand-in for tests: cites the first evidence blocks it was given."""

    provider = "mock"
    model = "mock-deterministic"

    def generate(self, system: str, user: str) -> LLMResult:
        blocks = _EVIDENCE_ID.findall(user)[:3]
        if not blocks:
            text = "The provided evidence is insufficient to answer this question."
        else:
            sentences = [f"{title} is described in the evidence [{eid}]." for eid, title in blocks]
            text = (
                "Source facts: "
                + " ".join(sentences)
                + ("\n\nAnalysis: prioritise patching according to the cited sources.")
            )
        return LLMResult(text=text, provider=self.provider, model=self.model, latency_ms=0.0)


def build_llm(settings: Settings) -> LLMProvider | None:
    timeout, tokens, temp = (
        settings.llm_timeout_seconds,
        settings.llm_max_tokens,
        settings.llm_temperature,
    )
    if settings.llm_provider == "ollama":
        return OllamaProvider(
            settings.ollama_base_url,
            settings.llm_model,
            timeout_seconds=timeout,
            max_tokens=tokens,
            temperature=temp,
        )
    if settings.llm_provider == "openai_compatible":
        if not settings.llm_base_url or not settings.llm_api_key:  # also enforced by Settings
            raise ValueError("openai_compatible requires LLM_BASE_URL and LLM_API_KEY")
        return OpenAICompatibleProvider(
            settings.llm_base_url,
            settings.llm_api_key.get_secret_value(),
            settings.llm_model,
            timeout_seconds=timeout,
            max_tokens=tokens,
            temperature=temp,
        )
    if settings.llm_provider == "mock":
        return MockProvider()
    return None
