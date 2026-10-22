"""LLM providers behind one small interface.

* ``OllamaProvider``: local inference through Ollama's ``/api/chat`` (primary option).
* ``OpenAICompatibleProvider``: any ``/chat/completions`` endpoint; only built when
  explicitly configured, because evidence and questions are sent to that third party.
* ``GeminiProvider``: Google's Gemini API through the official ``google-genai`` SDK; only
  built when selected and configured, because evidence and questions are sent to Google.
* ``MockProvider``: deterministic, network-free answers for automated tests.

Providers raise ``LLMUnavailableError`` (not running, model missing, HTTP error, rate
limit, blocked answer) or ``LLMTimeoutError``; the RAG pipeline turns both into an
evidence-only answer, so its refusal, relevance and citation checks always still apply.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from typing import Protocol

import httpx
from google.genai import errors as genai_errors
from google.genai import types as genai_types

from app.core.config import Settings
from app.core.gemini import Cooldown, GeminiFailure, classify_error, make_client

logger = logging.getLogger(__name__)


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


# Finish reasons whose text may be shown. Any other reason (SAFETY, RECITATION,
# PROHIBITED_CONTENT, ...) means the answer was stopped, so none of it is used.
_GEMINI_USABLE_FINISH = frozenset({"STOP", "MAX_TOKENS", "FINISH_REASON_UNSPECIFIED", ""})


class GeminiProvider:
    provider = "gemini"

    def __init__(
        self,
        api_key: str,
        model: str,
        *,
        timeout_seconds: float,
        max_tokens: int,
        temperature: float,
        thinking_budget: int | None = None,
        http_client: httpx.Client | None = None,
        cooldown: Cooldown | None = None,
    ) -> None:
        self.model = model.removeprefix("models/")
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.thinking_budget = thinking_budget
        self._client = make_client(
            api_key, timeout_seconds=timeout_seconds, http_client=http_client
        )
        self.cooldown = cooldown or Cooldown()

    def generate(self, system: str, user: str) -> LLMResult:
        if (wait := self.cooldown.remaining()) > 0:
            # Recently rate limited: answer from evidence now rather than wait or retry.
            raise LLMUnavailableError(
                f"Gemini rate limit or quota reached; not retrying for about {round(wait)} s"
            )
        config = genai_types.GenerateContentConfig(
            system_instruction=system,
            max_output_tokens=self.max_tokens,
            temperature=self.temperature,
            candidate_count=1,
            # No tools are offered, so the SDK's function-calling loop stays off.
            automatic_function_calling=genai_types.AutomaticFunctionCallingConfig(disable=True),
            # Safety settings are deliberately left at Google's defaults: never loosened.
            thinking_config=(
                genai_types.ThinkingConfig(thinking_budget=self.thinking_budget)
                if self.thinking_budget is not None
                else None
            ),
        )
        started = time.perf_counter()
        try:
            response = self._client.models.generate_content(
                model=self.model, contents=user, config=config
            )
        except (genai_errors.APIError, httpx.HTTPError) as exc:
            failure = classify_error(exc, self.model) or GeminiFailure("server", "Gemini API error")
            self.cooldown.trip(failure)
            logger.warning(
                "Gemini generation failed",
                extra={"failure": failure.kind, "error_type": type(exc).__name__},
            )
            if failure.kind == "timeout":
                raise LLMTimeoutError(failure.message) from exc
            raise LLMUnavailableError(failure.message) from exc
        except Exception as exc:  # e.g. a response the SDK cannot parse
            logger.warning("Gemini call failed", extra={"error_type": type(exc).__name__})
            raise LLMUnavailableError("Gemini returned an unexpected response") from exc
        return self._result(response, started)

    def _result(self, response: genai_types.GenerateContentResponse, started: float) -> LLMResult:
        feedback = response.prompt_feedback
        if feedback is not None and feedback.block_reason is not None:
            raise LLMUnavailableError(
                f"Gemini blocked the request ({_enum_name(feedback.block_reason)})"
            )
        if not response.candidates:
            raise LLMUnavailableError("Gemini returned no answer")
        candidate = response.candidates[0]
        finish = _enum_name(candidate.finish_reason)
        if finish not in _GEMINI_USABLE_FINISH:
            raise LLMUnavailableError(f"Gemini stopped the answer ({finish})")
        parts = (candidate.content.parts if candidate.content else None) or []
        # Thought summaries are never part of the answer.
        text = "".join(p.text for p in parts if p.text and not p.thought).strip()
        if not text:
            if finish == "MAX_TOKENS":
                raise LLMUnavailableError(
                    "Gemini used the whole output budget before answering; "
                    "raise LLM_MAX_TOKENS or lower GEMINI_THINKING_BUDGET"
                )
            raise LLMUnavailableError("Gemini returned an empty answer")
        return LLMResult(
            text=text,
            provider=self.provider,
            model=self.model,
            latency_ms=round((time.perf_counter() - started) * 1000, 1),
            truncated=finish == "MAX_TOKENS",
        )


def _enum_name(value: object) -> str:
    if value is None:
        return ""
    return str(getattr(value, "value", value))


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
    if settings.llm_provider == "gemini":
        problem = settings.gemini_problem("llm")
        if problem or settings.gemini_api_key is None or settings.gemini_model is None:
            # Missing credentials must not stop the API: chat answers from evidence and
            # /health/ready reports why.
            logger.warning("%s; chat will return evidence-only answers", problem)
            return None
        return GeminiProvider(
            settings.gemini_api_key.get_secret_value(),
            settings.gemini_model,
            timeout_seconds=timeout,
            max_tokens=tokens,
            temperature=temp,
            thinking_budget=settings.gemini_thinking_budget,
        )
    if settings.llm_provider == "mock":
        return MockProvider()
    return None
