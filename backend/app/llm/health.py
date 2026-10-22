"""Readiness probe for the language model (degraded, never fatal: chat falls back to
evidence-only answers)."""

from __future__ import annotations

from typing import Any

from app.api.routes.health import ReadinessCheck
from app.llm.providers import MockProvider, OllamaProvider


def llm_probe(app: Any) -> ReadinessCheck:
    llm = app.state.llm
    if llm is None:
        return ReadinessCheck(status="degraded", detail="disabled; chat returns evidence only")
    if isinstance(llm, MockProvider):
        return ReadinessCheck(status="degraded", detail="mock provider (testing only)")
    if isinstance(llm, OllamaProvider):
        ok, detail = llm.ping()
        return ReadinessCheck(status="ok" if ok else "degraded", detail=detail)
    return ReadinessCheck(status="ok", detail=f"{llm.provider}/{llm.model} (not probed)")
