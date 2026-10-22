"""Shared plumbing for the Google Gemini API (official ``google-genai`` SDK).

Used by the Gemini LLM provider (``app.llm.providers``) and the Gemini embedder
(``app.retrieval.embedders``). Three rules apply to every call:

* The API key comes only from backend settings (``GEMINI_API_KEY``) and is sent by the
  SDK in the ``x-goog-api-key`` header, never in a URL.
* SDK retries are disabled: a rate limit or quota error is reported at once so chat can
  fall back to evidence-only answers instead of hanging. Callers decide whether to wait.
* Error messages are built from the HTTP status and the error's machine-readable fields
  only. Response bodies are never echoed, to users or to logs.
"""

from __future__ import annotations

import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

import httpx
from google import genai
from google.genai import errors, types

# How long to stop calling the API after a quota error without a retry hint. Daily
# free-tier quotas reset once a day, so retrying every request would only add latency.
QUOTA_COOLDOWN_SECONDS = 600.0
DEFAULT_RATE_LIMIT_COOLDOWN_SECONDS = 30.0

FailureKind = Literal[
    "rate_limited",
    "quota_exhausted",
    "timeout",
    "auth",
    "not_found",
    "bad_request",
    "server",
    "network",
]


def make_client(
    api_key: str, *, timeout_seconds: float, http_client: httpx.Client | None = None
) -> genai.Client:
    """Build an SDK client with a request timeout and without automatic retries.

    ``http_client`` lets tests inject an ``httpx.MockTransport``; production code leaves it
    unset and the SDK manages its own connection pool.
    """
    options = types.HttpOptions(
        timeout=int(timeout_seconds * 1000),  # the SDK expects milliseconds
        retry_options=types.HttpRetryOptions(attempts=1),
        httpx_client=http_client,
    )
    return genai.Client(api_key=api_key, http_options=options)


@dataclass(frozen=True)
class GeminiFailure:
    kind: FailureKind
    message: str  # safe to show to users and to log: no response body, no key
    retry_after: float | None = None


def _error_details(exc: errors.APIError) -> list[dict[str, Any]]:
    body = exc.details if isinstance(exc.details, dict) else {}
    error = body.get("error", body)
    details = error.get("details") if isinstance(error, dict) else None
    return [d for d in details if isinstance(d, dict)] if isinstance(details, list) else []


def _retry_delay(details: list[dict[str, Any]]) -> float | None:
    for detail in details:
        if str(detail.get("@type", "")).endswith("google.rpc.RetryInfo"):
            match = re.fullmatch(r"(\d+(?:\.\d+)?)s", str(detail.get("retryDelay", "")))
            if match:
                return float(match.group(1))
    return None


def _is_daily_quota(details: list[dict[str, Any]]) -> bool:
    for detail in details:
        if str(detail.get("@type", "")).endswith("google.rpc.QuotaFailure"):
            for violation in detail.get("violations") or []:
                if isinstance(violation, dict) and "perday" in str(
                    violation.get("quotaId", "")
                ).lower().replace("_", ""):
                    return True
    return False


def _has_reason(details: list[dict[str, Any]], reason: str) -> bool:
    return any(
        str(d.get("@type", "")).endswith("google.rpc.ErrorInfo") and d.get("reason") == reason
        for d in details
    )


def classify_error(exc: BaseException, model: str) -> GeminiFailure | None:
    """Map an SDK or transport exception to a failure kind; None if it is not one of ours."""
    if isinstance(exc, httpx.TimeoutException):
        return GeminiFailure("timeout", "Gemini did not answer in time")
    if isinstance(exc, httpx.HTTPError):
        return GeminiFailure("network", f"Gemini API not reachable ({type(exc).__name__})")
    if not isinstance(exc, errors.APIError):
        return None
    code = exc.code if isinstance(exc.code, int) else 0
    status = exc.status if isinstance(exc.status, str) else ""
    label = f"HTTP {code} {status}".strip()
    details = _error_details(exc)
    if code == 429 or status == "RESOURCE_EXHAUSTED":
        delay = _retry_delay(details)
        if _is_daily_quota(details):
            return GeminiFailure(
                "quota_exhausted",
                "the Gemini daily quota for this API key is exhausted",
                retry_after=delay,
            )
        wait = f"; retry in about {round(delay)} s" if delay is not None else ""
        return GeminiFailure(
            "rate_limited", f"Gemini rate limit or quota reached{wait}", retry_after=delay
        )
    if code in (401, 403) or _has_reason(details, "API_KEY_INVALID"):
        return GeminiFailure("auth", f"Gemini rejected the API key ({label}); check GEMINI_API_KEY")
    if code == 404:
        return GeminiFailure(
            "not_found",
            f"Gemini model {model!r} not found ({label}); "
            "list available models with `python -m app.llm.gemini_models`",
        )
    if 400 <= code < 500:
        return GeminiFailure("bad_request", f"Gemini rejected the request ({label})")
    return GeminiFailure("server", f"Gemini API error ({label})")


class Cooldown:
    """Stops calls for a while after a rate-limit or quota error (thread-safe)."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._until = 0.0
        self._lock = threading.Lock()

    def remaining(self) -> float:
        with self._lock:
            return max(0.0, self._until - self._clock())

    def trip(self, failure: GeminiFailure) -> None:
        if failure.kind == "quota_exhausted":
            seconds = max(failure.retry_after or 0.0, QUOTA_COOLDOWN_SECONDS)
        elif failure.kind == "rate_limited":
            seconds = failure.retry_after or DEFAULT_RATE_LIMIT_COOLDOWN_SECONDS
        else:
            return
        with self._lock:
            self._until = max(self._until, self._clock() + seconds)

    def reset(self) -> None:
        with self._lock:
            self._until = 0.0
