"""Shared schema types."""

from __future__ import annotations

from typing import Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]


class Page(BaseModel, Generic[T]):
    items: list[T]
    page: int = Field(ge=1)
    page_size: int = Field(ge=1)
    total: int = Field(ge=0)


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)
