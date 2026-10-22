"""Shared FastAPI dependencies and parameter types."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Path, Query
from sqlalchemy.orm import Session

from app.db.session import get_db_session

DbSession = Annotated[Session, Depends(get_db_session)]

CveIdPath = Annotated[
    str,
    Path(
        pattern=r"^[Cc][Vv][Ee]-\d{4}-\d{4,7}$", description="CVE identifier, e.g. CVE-2021-44228"
    ),
]
TechniqueIdPath = Annotated[
    str, Path(pattern=r"^[Tt]\d{4}(\.\d{3})?$", description="ATT&CK technique ID, e.g. T1190")
]
PageQuery = Annotated[int, Query(ge=1, le=1000, description="1-based page number")]
PageSizeQuery = Annotated[int, Query(ge=1, le=100, description="Items per page (max 100)")]
SearchText = Annotated[str | None, Query(min_length=1, max_length=200)]
