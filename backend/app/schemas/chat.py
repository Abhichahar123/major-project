"""Chat (RAG) request and response schemas."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from app.schemas.common import Severity


class ChatFilters(BaseModel):
    severity: list[Severity] = Field(default_factory=list, max_length=5)
    in_kev: bool | None = None
    entity_types: list[Literal["vulnerability", "kev", "attack_technique"]] = Field(
        default_factory=list, max_length=3
    )


class ChatRequest(BaseModel):
    question: str = Field(min_length=3, max_length=1000)
    filters: ChatFilters = Field(default_factory=ChatFilters)
    top_k: int | None = Field(default=None, ge=1, le=20)

    @field_validator("question")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if len(value.strip()) < 3:
            raise ValueError("question must contain at least 3 non-space characters")
        return value


class CitationOut(BaseModel):
    id: str
    entity_type: str
    entity_id: str
    cve_id: str | None
    title: str
    source_name: str
    source_url: str | None
    snippet: str


class SourceFactOut(BaseModel):
    cve_id: str
    record_url: str
    severity: str | None
    cvss_base_score: float | None
    cvss_version: str | None
    cvss_provider: str | None
    in_kev: bool
    kev_date_added: str | None
    known_ransomware_use: str | None
    cwes: list[str]


class ChatResponse(BaseModel):
    question: str
    answer: str
    mode: Literal["generated", "evidence_only", "insufficient_evidence", "refused"]
    grounded: bool = Field(
        description="True only when the answer cites provided evidence and introduces no "
        "CVE IDs absent from that evidence"
    )
    citations: list[CitationOut]
    cve_ids: list[str]
    facts: list[SourceFactOut] = Field(description="Values read from the database, not the model")
    warnings: list[str]
    model: dict[str, str] | None
    retrieval: dict[str, Any]
    prompt_version: str
    latency_ms: float
    disclaimer: str
