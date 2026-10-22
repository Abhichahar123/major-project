"""Ingestion job lifecycle.

``create_job`` inserts a queued job; the partial unique index on ``ingestion_jobs`` makes
the database reject a second active job for the same source. ``execute_job`` runs the
source adapter and records counts, per-record errors and the final status. The source
watermark is advanced only when the job succeeds.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.logging import redact
from app.db.models import IngestionError, IngestionJob, Source
from app.ingestion.http import SourceHttpClient
from app.ingestion.store import Change, get_source

logger = logging.getLogger(__name__)

MAX_STORED_ERRORS = 500
MAX_ERROR_LENGTH = 1000


class JobConflictError(Exception):
    """Another job for this source is already queued or running."""


class UnknownSourceError(ValueError):
    pass


@dataclass
class JobContext:
    """What an adapter needs: configuration, HTTP, sessions, counters and error sink."""

    job_id: int
    source_id: int
    source_code: str
    params: dict[str, Any]
    settings: Settings
    http: SourceHttpClient
    session_factory: sessionmaker[Session]
    watermark: dict[str, Any] | None
    new_watermark: dict[str, Any] | None = None
    details: dict[str, Any] = field(default_factory=dict)
    fetched: int = 0
    inserted: int = 0
    updated: int = 0
    unchanged: int = 0
    failed: int = 0
    errors: list[tuple[str | None, str, str]] = field(default_factory=list)

    def count(self, change: Change) -> None:
        if change is Change.INSERTED:
            self.inserted += 1
        elif change is Change.UPDATED:
            self.updated += 1
        else:
            self.unchanged += 1

    def fail(self, record_key: str | None, stage: str, message: str) -> None:
        self.failed += 1
        if len(self.errors) < MAX_STORED_ERRORS:
            self.errors.append((record_key, stage, redact(message)[:MAX_ERROR_LENGTH]))

    def flush_progress(self) -> None:
        """Persist counters so job progress is visible while the job runs."""
        with self.session_factory.begin() as session:
            session.execute(
                update(IngestionJob)
                .where(IngestionJob.id == self.job_id)
                .values(
                    records_fetched=self.fetched,
                    records_inserted=self.inserted,
                    records_updated=self.updated,
                    records_unchanged=self.unchanged,
                    records_failed=self.failed,
                )
            )


class Adapter(Protocol):
    code: str

    def validate_params(self, params: dict[str, Any]) -> dict[str, Any]: ...

    def run(self, ctx: JobContext) -> None: ...


def _now() -> datetime:
    return datetime.now(UTC)


def fail_stale_jobs(session: Session, settings: Settings) -> int:
    """Mark jobs stuck in queued/running (e.g. after a crash) as failed."""
    cutoff = _now() - timedelta(minutes=settings.ingestion_stale_job_minutes)
    result = session.execute(
        update(IngestionJob)
        .where(
            IngestionJob.status.in_(["queued", "running"]),
            IngestionJob.created_at < cutoff,
        )
        .values(status="failed", finished_at=_now(), error_summary="marked stale: no progress")
    )
    return result.rowcount or 0  # type: ignore[attr-defined]


def create_job(
    session_factory: sessionmaker[Session],
    settings: Settings,
    adapter: Adapter,
    params: dict[str, Any],
    trigger: str,
) -> int:
    validated = adapter.validate_params(params)
    try:
        with session_factory.begin() as session:
            fail_stale_jobs(session, settings)
            source = get_source(session, adapter.code)
            job = IngestionJob(
                source_id=source.id, status="queued", trigger=trigger, params=validated
            )
            session.add(job)
            session.flush()
            return job.id
    except IntegrityError as exc:
        raise JobConflictError(f"a {adapter.code} job is already queued or running") from exc


def execute_job(
    job_id: int,
    adapter: Adapter,
    settings: Settings,
    session_factory: sessionmaker[Session],
    http_factory: Callable[[], SourceHttpClient],
) -> IngestionJob:
    with session_factory.begin() as session:
        job = session.get(IngestionJob, job_id)
        if job is None:
            raise LookupError(f"job {job_id} not found")
        source = session.get(Source, job.source_id)
        if source is None:
            raise LookupError(f"source for job {job_id} not found")
        job.status = "running"
        job.started_at = _now()
        ctx_args = {
            "job_id": job.id,
            "source_id": source.id,
            "source_code": source.code,
            "params": dict(job.params or {}),
            "watermark": dict(source.watermark) if source.watermark else None,
        }

    status = "succeeded"
    summary: str | None = None
    with http_factory() as http:
        ctx = JobContext(settings=settings, http=http, session_factory=session_factory, **ctx_args)  # type: ignore[arg-type]
        logger.info("Ingestion job started", extra={"job_id": job_id, "source": ctx.source_code})
        try:
            adapter.run(ctx)
        except Exception as exc:  # the job must always reach a final state
            status = "failed"
            summary = redact(f"{type(exc).__name__}: {exc}")[:MAX_ERROR_LENGTH]
            logger.exception("Ingestion job failed", extra={"job_id": job_id})
        else:
            succeeded = ctx.inserted + ctx.updated + ctx.unchanged
            if ctx.failed and succeeded:
                status = "partial"
                summary = f"{ctx.failed} record(s) failed; see job errors"
            elif ctx.failed:
                status = "failed"
                summary = f"all {ctx.failed} record(s) failed; see job errors"

    with session_factory.begin() as session:
        job = session.get(IngestionJob, job_id)
        if job is None:
            raise LookupError(f"job {job_id} disappeared while running")
        job.status = status
        job.finished_at = _now()
        job.records_fetched = ctx.fetched
        job.records_inserted = ctx.inserted
        job.records_updated = ctx.updated
        job.records_unchanged = ctx.unchanged
        job.records_failed = ctx.failed
        job.error_summary = summary
        job.details = ctx.details or None
        for record_key, stage, message in ctx.errors:
            session.add(
                IngestionError(job_id=job_id, record_key=record_key, stage=stage, message=message)
            )
        if status in {"succeeded", "partial"}:
            source = session.get(Source, job.source_id)
            if source is None:
                raise LookupError(f"source for job {job_id} not found")
            source.last_success_at = job.finished_at
            # A partial run may have skipped records, so it must not move the cursor.
            if status == "succeeded" and ctx.new_watermark is not None:
                source.watermark = ctx.new_watermark
        session.flush()
        session.expunge(job)
    logger.info(
        "Ingestion job finished",
        extra={
            "job_id": job_id,
            "status": status,
            "inserted": ctx.inserted,
            "updated": ctx.updated,
            "unchanged": ctx.unchanged,
            "failed": ctx.failed,
        },
    )
    return job


def run_now(
    adapter: Adapter,
    params: dict[str, Any],
    settings: Settings,
    session_factory: sessionmaker[Session],
    http_factory: Callable[[], SourceHttpClient],
    trigger: str = "cli",
) -> IngestionJob:
    job_id = create_job(session_factory, settings, adapter, params, trigger)
    return execute_job(job_id, adapter, settings, session_factory, http_factory)


def latest_jobs(session: Session, limit: int = 20) -> list[IngestionJob]:
    return list(session.scalars(select(IngestionJob).order_by(IngestionJob.id.desc()).limit(limit)))
