"""ORM models.

Tables fall into four groups:

* provenance: ``sources``, ``ingestion_jobs``, ``ingestion_errors``, ``source_records``
* vulnerability facts: ``vulnerabilities`` and its child tables, ``kev_entries``
* threat knowledge: ``attack_techniques``, ``capec_patterns`` and their CWE/ATT&CK mappings
* retrieval: ``document_chunks``, ``embedding_models``, ``chunk_embeddings``

Child rows of a vulnerability carry ``ingest_source`` (which pipeline wrote them, e.g.
``cve5`` or ``nvd``) and ``provider`` (who published the value, e.g. ``GitHub_M``,
``CISA-ADP``, ``nvd@nist.gov``). Re-ingesting one source therefore only replaces that
source's rows.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Computed,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, TSVECTOR
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

# Fixed by migration; see docs/architecture.md before changing.
EMBEDDING_DIMENSION = 768

JOB_STATUSES = ("queued", "running", "succeeded", "partial", "failed")
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE")


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


# --------------------------------------------------------------------------- provenance


class Source(TimestampMixin, Base):
    """A registered upstream data source."""

    __tablename__ = "sources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    url: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    # Source-specific incremental cursor, e.g. {"fetch_time": "..."}; advanced only on success.
    watermark: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    jobs: Mapped[list[IngestionJob]] = relationship(back_populates="source")


class IngestionJob(Base):
    __tablename__ = "ingestion_jobs"
    __table_args__ = (
        CheckConstraint(f"status IN {JOB_STATUSES!r}", name="status_valid"),
        # At most one active job per source, enforced by the database.
        Index(
            "uq_ingestion_jobs_one_active_per_source",
            "source_id",
            unique=True,
            postgresql_where=text("status IN ('queued', 'running')"),
        ),
        Index("ix_ingestion_jobs_source_started", "source_id", "started_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")
    trigger: Mapped[str] = mapped_column(String(16), nullable=False, default="cli")
    params: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    records_fetched: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    records_inserted: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    records_updated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    records_unchanged: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    records_failed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_summary: Mapped[str | None] = mapped_column(Text)

    source: Mapped[Source] = relationship(back_populates="jobs")
    errors: Mapped[list[IngestionError]] = relationship(
        back_populates="job", cascade="all, delete-orphan"
    )


class IngestionError(Base):
    __tablename__ = "ingestion_errors"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    job_id: Mapped[int] = mapped_column(
        ForeignKey("ingestion_jobs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    record_key: Mapped[str | None] = mapped_column(String(200))
    stage: Mapped[str] = mapped_column(String(32), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    job: Mapped[IngestionJob] = relationship(back_populates="errors")


class SourceRecord(Base):
    """Provenance for each upstream record: where it came from and its content hash."""

    __tablename__ = "source_records"
    __table_args__ = (UniqueConstraint("source_id", "record_key"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id"), nullable=False)
    record_key: Mapped[str] = mapped_column(String(200), nullable=False)
    source_url: Mapped[str | None] = mapped_column(String(1000))
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_job_id: Mapped[int | None] = mapped_column(
        ForeignKey("ingestion_jobs.id", ondelete="SET NULL")
    )


# ----------------------------------------------------------------- vulnerability facts


class Vulnerability(TimestampMixin, Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (
        CheckConstraint(r"cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'", name="cve_id_format"),
        CheckConstraint(f"severity IS NULL OR severity IN {SEVERITIES!r}", name="severity_valid"),
        CheckConstraint(
            "cvss_base_score IS NULL OR (cvss_base_score >= 0 AND cvss_base_score <= 10)",
            name="cvss_range",
        ),
        Index("ix_vulnerabilities_search_tsv", "search_tsv", postgresql_using="gin"),
        Index("ix_vulnerabilities_published_at", "published_at"),
        Index("ix_vulnerabilities_severity", "severity"),
        Index("ix_vulnerabilities_cvss_base_score", "cvss_base_score"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(24), unique=True, nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False)  # PUBLISHED / REJECTED
    title: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    assigner: Mapped[str | None] = mapped_column(String(100))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Display values derived from cvss_metrics by the documented precedence rule.
    severity: Mapped[str | None] = mapped_column(String(10))
    cvss_base_score: Mapped[float | None] = mapped_column(Float)
    cvss_version: Mapped[str | None] = mapped_column(String(8))
    cvss_provider: Mapped[str | None] = mapped_column(String(100))
    search_tsv: Mapped[str] = mapped_column(
        TSVECTOR,
        Computed(
            "setweight(to_tsvector('english', coalesce(cve_id, '')), 'A') || "
            "setweight(to_tsvector('english', coalesce(title, '')), 'A') || "
            "setweight(to_tsvector('english', coalesce(description, '')), 'B')",
            persisted=True,
        ),
    )

    cvss_metrics: Mapped[list[CvssMetric]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )
    cwes: Mapped[list[VulnerabilityCwe]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )
    affected_products: Mapped[list[AffectedProduct]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )
    references: Mapped[list[VulnReference]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )


class CvssMetric(Base):
    __tablename__ = "cvss_metrics"
    __table_args__ = (
        UniqueConstraint("vulnerability_id", "ingest_source", "provider", "version"),
        CheckConstraint("base_score >= 0 AND base_score <= 10", name="score_range"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    vulnerability_id: Mapped[int] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    ingest_source: Mapped[str] = mapped_column(String(32), nullable=False)
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    version: Mapped[str] = mapped_column(String(8), nullable=False)  # "2.0" "3.0" "3.1" "4.0"
    vector: Mapped[str | None] = mapped_column(String(200))
    base_score: Mapped[float] = mapped_column(Float, nullable=False)
    base_severity: Mapped[str | None] = mapped_column(String(10))

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="cvss_metrics")


class CweEntry(Base):
    __tablename__ = "cwe_entries"
    __table_args__ = (CheckConstraint(r"cwe_id ~ '^CWE-[0-9]+$'", name="cwe_id_format"),)

    cwe_id: Mapped[str] = mapped_column(String(16), primary_key=True)
    name: Mapped[str | None] = mapped_column(Text)


class VulnerabilityCwe(Base):
    __tablename__ = "vulnerability_cwes"

    vulnerability_id: Mapped[int] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"), primary_key=True
    )
    cwe_id: Mapped[str] = mapped_column(
        ForeignKey("cwe_entries.cwe_id"), primary_key=True, index=True
    )
    ingest_source: Mapped[str] = mapped_column(String(32), primary_key=True)
    provider: Mapped[str] = mapped_column(String(100), primary_key=True)

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="cwes")
    cwe: Mapped[CweEntry] = relationship()


class AffectedProduct(Base):
    """An affected vendor/product as stated by a provider, with its raw version entries.

    ``versions`` keeps the provider's version objects (CVE JSON 5 ``versions`` items, or
    the equivalent built from NVD CPE matches). They are interpreted at match time because
    version schemes differ by product.
    """

    __tablename__ = "affected_products"
    __table_args__ = (
        Index("ix_affected_products_product_lower", func.lower(text("product"))),
        Index("ix_affected_products_package_lower", func.lower(text("package_name"))),
        Index("ix_affected_products_vendor_lower", func.lower(text("vendor"))),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    vulnerability_id: Mapped[int] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    ingest_source: Mapped[str] = mapped_column(String(32), nullable=False)
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    vendor: Mapped[str | None] = mapped_column(String(300))
    product: Mapped[str | None] = mapped_column(String(300))
    package_name: Mapped[str | None] = mapped_column(String(300))
    collection_url: Mapped[str | None] = mapped_column(String(500))
    ecosystem: Mapped[str | None] = mapped_column(String(32))
    default_status: Mapped[str | None] = mapped_column(String(16))
    cpes: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False, default=list)
    versions: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="affected_products")


class VulnReference(Base):
    __tablename__ = "vuln_references"
    __table_args__ = (UniqueConstraint("vulnerability_id", "url"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    vulnerability_id: Mapped[int] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False
    )
    url: Mapped[str] = mapped_column(String(2000), nullable=False)
    ingest_source: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str | None] = mapped_column(Text)
    tags: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False, default=list)

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="references")


class KevEntry(TimestampMixin, Base):
    """CISA Known Exploited Vulnerabilities catalog entry (joined to CVEs by cve_id)."""

    __tablename__ = "kev_entries"
    __table_args__ = (
        CheckConstraint(r"cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'", name="cve_id_format"),
        Index("ix_kev_entries_date_added", "date_added"),
        Index("ix_kev_entries_vendor_lower", func.lower(text("vendor_project"))),
    )

    cve_id: Mapped[str] = mapped_column(String(24), primary_key=True)
    vendor_project: Mapped[str] = mapped_column(String(300), nullable=False)
    product: Mapped[str] = mapped_column(String(300), nullable=False)
    vulnerability_name: Mapped[str] = mapped_column(Text, nullable=False)
    short_description: Mapped[str] = mapped_column(Text, nullable=False)
    required_action: Mapped[str] = mapped_column(Text, nullable=False)
    notes: Mapped[str | None] = mapped_column(Text)
    date_added: Mapped[date] = mapped_column(Date, nullable=False)
    due_date: Mapped[date | None] = mapped_column(Date)
    known_ransomware_use: Mapped[str] = mapped_column(String(16), nullable=False)
    cwes: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False, default=list)
    catalog_version: Mapped[str | None] = mapped_column(String(32))


# ------------------------------------------------------------------- threat knowledge


class AttackTechnique(TimestampMixin, Base):
    __tablename__ = "attack_techniques"
    __table_args__ = (
        Index("ix_attack_techniques_tactics", "tactics", postgresql_using="gin"),
        Index(
            "ix_attack_techniques_search",
            text("to_tsvector('english', name || ' ' || coalesce(description, ''))"),
            postgresql_using="gin",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    stix_id: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    technique_id: Mapped[str] = mapped_column(String(16), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    tactics: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False, default=list)
    platforms: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False, default=list)
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    parent_technique_id: Mapped[str | None] = mapped_column(String(16))
    url: Mapped[str | None] = mapped_column(String(500))
    deprecated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    attack_version: Mapped[str | None] = mapped_column(String(16))
    source_modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class CapecPattern(TimestampMixin, Base):
    __tablename__ = "capec_patterns"

    capec_id: Mapped[str] = mapped_column(String(16), primary_key=True)
    stix_id: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    url: Mapped[str | None] = mapped_column(String(500))
    status: Mapped[str | None] = mapped_column(String(16))
    abstraction: Mapped[str | None] = mapped_column(String(16))
    likelihood: Mapped[str | None] = mapped_column(String(16))
    typical_severity: Mapped[str | None] = mapped_column(String(16))


class CapecCweMapping(Base):
    """CAPEC pattern lists the CWE as a related weakness (published by MITRE CAPEC)."""

    __tablename__ = "capec_cwe_mappings"

    capec_id: Mapped[str] = mapped_column(
        ForeignKey("capec_patterns.capec_id", ondelete="CASCADE"), primary_key=True
    )
    cwe_id: Mapped[str] = mapped_column(String(16), primary_key=True, index=True)


class CapecAttackMapping(Base):
    """CAPEC pattern's published ATT&CK taxonomy mapping (MITRE CAPEC)."""

    __tablename__ = "capec_attack_mappings"

    capec_id: Mapped[str] = mapped_column(
        ForeignKey("capec_patterns.capec_id", ondelete="CASCADE"), primary_key=True
    )
    technique_id: Mapped[str] = mapped_column(String(16), primary_key=True, index=True)


# -------------------------------------------------------------------------- retrieval


class DocumentChunk(Base):
    """A retrievable text chunk derived from one entity (CVE, KEV entry or technique)."""

    __tablename__ = "document_chunks"
    __table_args__ = (
        UniqueConstraint("entity_type", "entity_id", "chunk_index"),
        Index("ix_document_chunks_tsv", "tsv", postgresql_using="gin"),
        Index("ix_document_chunks_cve_id", "cve_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(64), nullable=False)
    cve_id: Mapped[str | None] = mapped_column(String(24))
    chunk_index: Mapped[int] = mapped_column(Integer, nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    source_name: Mapped[str] = mapped_column(String(100), nullable=False)
    source_url: Mapped[str | None] = mapped_column(String(1000))
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )
    tsv: Mapped[str] = mapped_column(
        TSVECTOR,
        Computed(
            "setweight(to_tsvector('english', coalesce(title, '')), 'A') || "
            "setweight(to_tsvector('english', coalesce(content, '')), 'B')",
            persisted=True,
        ),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    embeddings: Mapped[list[ChunkEmbedding]] = relationship(
        back_populates="chunk", cascade="all, delete-orphan"
    )


class EmbeddingModel(Base):
    __tablename__ = "embedding_models"
    __table_args__ = (UniqueConstraint("provider", "name", "dimension"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    dimension: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class ChunkEmbedding(Base):
    __tablename__ = "chunk_embeddings"
    __table_args__ = (
        Index(
            "ix_chunk_embeddings_hnsw",
            "embedding",
            postgresql_using="hnsw",
            postgresql_ops={"embedding": "vector_cosine_ops"},
        ),
    )

    chunk_id: Mapped[int] = mapped_column(
        ForeignKey("document_chunks.id", ondelete="CASCADE"), primary_key=True
    )
    model_id: Mapped[int] = mapped_column(
        ForeignKey("embedding_models.id", ondelete="CASCADE"), primary_key=True
    )
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    embedding: Mapped[list[float]] = mapped_column(Vector(EMBEDDING_DIMENSION), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    chunk: Mapped[DocumentChunk] = relationship(back_populates="embeddings")
