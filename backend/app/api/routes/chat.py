"""Evidence-grounded cybersecurity Q&A."""

from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, Depends, Request

from app.api.deps import DbSession
from app.core.rate_limit import rate_limit
from app.rag.pipeline import answer_question
from app.retrieval.search import RetrievalFilters
from app.schemas.chat import ChatRequest, ChatResponse

router = APIRouter(tags=["chat"], dependencies=[Depends(rate_limit("chat"))])


@router.post("/chat", response_model=ChatResponse)
def chat(body: ChatRequest, request: Request, db: DbSession) -> ChatResponse:
    """Answer a question from retrieved evidence, with citations and database facts.

    ``mode`` is ``generated`` (LLM answer), ``evidence_only`` (LLM unavailable: the
    evidence is returned instead), ``insufficient_evidence`` (nothing relevant was found;
    the model is not called) or ``refused`` (offensive request).
    """
    state = request.app.state
    filters = RetrievalFilters(
        severity=list(body.filters.severity),
        in_kev=body.filters.in_kev,
        entity_types=list(body.filters.entity_types),
    )
    result = answer_question(
        db,
        body.question,
        settings=state.settings,
        embedder=state.embedder,
        llm=state.llm,
        filters=filters,
        top_k=body.top_k,
    )
    return ChatResponse.model_validate(asdict(result))
