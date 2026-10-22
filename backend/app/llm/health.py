"""Readiness probe for the language model (degraded, never fatal: chat falls back to
evidence-only answers)."""

from __future__ import annotations

from typing import Any

from app.api.routes.health import ReadinessCheck
from app.llm.providers import GeminiProvider, MockProvider, OllamaProvider


def llm_probe(app: Any) -> ReadinessCheck:
    llm = app.state.llm
    if llm is None:
        settings = getattr(app.state, "settings", None)
        if settings is not None and settings.llm_provider == "gemini":
            problem = settings.gemini_problem("llm") or "Gemini is not configured"
            return ReadinessCheck(
                status="degraded", detail=f"{problem}; chat returns evidence only"
            )
        return ReadinessCheck(status="degraded", detail="disabled; chat returns evidence only")
    if isinstance(llm, MockProvider):
        return ReadinessCheck(status="degraded", detail="mock provider (testing only)")
    if isinstance(llm, OllamaProvider):
        ok, detail = llm.ping()
        return ReadinessCheck(status="ok" if ok else "degraded", detail=detail)
    if isinstance(llm, GeminiProvider):
        # Not probed: every call counts against the free-tier quota.
        if (wait := llm.cooldown.remaining()) > 0:
            return ReadinessCheck(
                status="degraded",
                detail=f"gemini/{llm.model}: rate limited for about {round(wait)} s",
            )
        return ReadinessCheck(status="ok", detail=f"gemini/{llm.model} (not probed)")
    return ReadinessCheck(status="ok", detail=f"{llm.provider}/{llm.model} (not probed)")
