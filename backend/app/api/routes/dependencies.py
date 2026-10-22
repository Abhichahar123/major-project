"""Dependency manifest analysis. Uploads are parsed in memory and never stored or run."""

from __future__ import annotations

import hashlib
import logging
from dataclasses import asdict
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, File, Request, UploadFile, status

from app.api.deps import DbSession
from app.core.exceptions import AppError
from app.core.rate_limit import rate_limit
from app.dependencies.matcher import analyze
from app.dependencies.parsers import MAX_BYTES, ManifestError, parse_manifest
from app.schemas.dependencies import DependencyReport

logger = logging.getLogger(__name__)

router = APIRouter(tags=["dependencies"], dependencies=[Depends(rate_limit("dependencies"))])


@router.post(
    "/dependencies/analyze",
    response_model=DependencyReport,
    responses={
        status.HTTP_413_CONTENT_TOO_LARGE: {"description": "File larger than 512 KB"},
        status.HTTP_415_UNSUPPORTED_MEDIA_TYPE: {"description": "Unsupported manifest type"},
        status.HTTP_422_UNPROCESSABLE_CONTENT: {"description": "File could not be parsed"},
    },
)
async def analyze_manifest(
    request: Request,
    db: DbSession,
    file: Annotated[
        UploadFile, File(description="requirements*.txt, package-lock.json or package.json")
    ],
) -> DependencyReport:
    filename = (file.filename or "").replace("\\", "/").rsplit("/", 1)[-1][:200]
    content = await file.read(MAX_BYTES + 1)
    if len(content) > MAX_BYTES:
        raise AppError(
            f"The file exceeds {MAX_BYTES // 1024} KB.",
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            code="file_too_large",
        )
    if not content:
        raise AppError("The file is empty.", status_code=422, code="empty_file")
    digest = hashlib.sha256(content).hexdigest()
    try:
        manifest = parse_manifest(filename, content)
    except ManifestError as exc:
        code = 415 if str(exc).startswith("unsupported file") else 422
        raise AppError(
            str(exc),
            status_code=code,
            code="unsupported_manifest" if code == 415 else "invalid_manifest",
        ) from None

    settings = request.app.state.settings
    client = None
    if settings.osv_online_lookup:
        client = request.app.state.osv_client_factory()
    try:
        report = analyze(db, manifest, client)
    finally:
        if client is not None:
            client.close()
    logger.info(
        "Dependency analysis",
        extra={
            "sha256": digest[:16],
            "format": manifest.format,
            "dependencies": report.dependency_count,
            "findings": len(report.findings),
        },
    )
    return DependencyReport(filename=filename, sha256=digest, **asdict(report))


def default_osv_client_factory(api_url: str, timeout: float) -> httpx.Client:
    return httpx.Client(
        base_url=api_url, timeout=timeout, headers={"User-Agent": "cti-platform-dependency-check"}
    )
