"""Initial schema: provenance, vulnerability facts, threat knowledge and retrieval.

Revision ID: 0001_initial
Revises:
Create Date: 2026-10-22 17:30:05.193060
"""

from collections.abc import Sequence

import pgvector.sqlalchemy
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


SOURCES = [
    {
        "code": "kev",
        "name": "CISA Known Exploited Vulnerabilities Catalog",
        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "description": "Vulnerabilities CISA has evidence of active exploitation for.",
    },
    {
        "code": "cve5",
        "name": "CVE Program records (CVE JSON 5)",
        "url": "https://github.com/CVEProject/cvelistV5",
        "description": "Official CVE records published by CNAs, including CISA-ADP enrichment.",
    },
    {
        "code": "nvd",
        "name": "NIST National Vulnerability Database (CVE API 2.0)",
        "url": "https://nvd.nist.gov/developers/vulnerabilities",
        "description": "NVD analysis: CVSS, CWE and CPE applicability statements.",
    },
    {
        "code": "attack",
        "name": "MITRE ATT&CK Enterprise",
        "url": "https://github.com/mitre-attack/attack-stix-data",
        "description": "Adversary tactics and techniques (STIX 2.1).",
    },
    {
        "code": "capec",
        "name": "MITRE CAPEC",
        "url": "https://github.com/mitre/cti",
        "description": "Attack patterns with published CWE and ATT&CK mappings (STIX 2.1).",
    },
    {
        "code": "embeddings",
        "name": "Retrieval index (derived)",
        "url": "internal://embeddings",
        "description": "Document chunks and embeddings derived from ingested records.",
    },
]


def upgrade() -> None:
    # pgvector must exist before the vector column is created. Requires a role allowed to
    # create extensions (the Compose database user is a superuser).
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    op.create_table(
        "attack_techniques",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("stix_id", sa.String(length=100), nullable=False),
        sa.Column("technique_id", sa.String(length=16), nullable=False),
        sa.Column("name", sa.String(length=300), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("tactics", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("platforms", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("is_subtechnique", sa.Boolean(), nullable=False),
        sa.Column("parent_technique_id", sa.String(length=16), nullable=True),
        sa.Column("url", sa.String(length=500), nullable=True),
        sa.Column("deprecated", sa.Boolean(), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.Column("attack_version", sa.String(length=16), nullable=True),
        sa.Column("source_modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_attack_techniques")),
        sa.UniqueConstraint("stix_id", name=op.f("uq_attack_techniques_stix_id")),
        sa.UniqueConstraint("technique_id", name=op.f("uq_attack_techniques_technique_id")),
    )
    op.create_index(
        "ix_attack_techniques_search",
        "attack_techniques",
        [sa.literal_column("to_tsvector('english', name || ' ' || coalesce(description, ''))")],
        unique=False,
        postgresql_using="gin",
    )
    op.create_index(
        "ix_attack_techniques_tactics",
        "attack_techniques",
        ["tactics"],
        unique=False,
        postgresql_using="gin",
    )
    op.create_table(
        "capec_patterns",
        sa.Column("capec_id", sa.String(length=16), nullable=False),
        sa.Column("stix_id", sa.String(length=100), nullable=False),
        sa.Column("name", sa.String(length=300), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("url", sa.String(length=500), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=True),
        sa.Column("abstraction", sa.String(length=16), nullable=True),
        sa.Column("likelihood", sa.String(length=16), nullable=True),
        sa.Column("typical_severity", sa.String(length=16), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("capec_id", name=op.f("pk_capec_patterns")),
        sa.UniqueConstraint("stix_id", name=op.f("uq_capec_patterns_stix_id")),
    )
    op.create_table(
        "cwe_entries",
        sa.Column("cwe_id", sa.String(length=16), nullable=False),
        sa.Column("name", sa.Text(), nullable=True),
        sa.CheckConstraint("cwe_id ~ '^CWE-[0-9]+$'", name=op.f("ck_cwe_entries_cwe_id_format")),
        sa.PrimaryKeyConstraint("cwe_id", name=op.f("pk_cwe_entries")),
    )
    op.create_table(
        "document_chunks",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("entity_type", sa.String(length=32), nullable=False),
        sa.Column("entity_id", sa.String(length=64), nullable=False),
        sa.Column("cve_id", sa.String(length=24), nullable=True),
        sa.Column("chunk_index", sa.Integer(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("source_name", sa.String(length=100), nullable=False),
        sa.Column("source_url", sa.String(length=1000), nullable=True),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "tsv",
            postgresql.TSVECTOR(),
            sa.Computed(
                "setweight(to_tsvector('english', coalesce(title, '')), 'A') || setweight(to_tsvector('english', coalesce(content, '')), 'B')",
                persisted=True,
            ),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_document_chunks")),
        sa.UniqueConstraint(
            "entity_type", "entity_id", "chunk_index", name=op.f("uq_document_chunks_entity_type")
        ),
    )
    op.create_index("ix_document_chunks_cve_id", "document_chunks", ["cve_id"], unique=False)
    op.create_index(
        "ix_document_chunks_tsv", "document_chunks", ["tsv"], unique=False, postgresql_using="gin"
    )
    op.create_table(
        "embedding_models",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("dimension", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_embedding_models")),
        sa.UniqueConstraint(
            "provider", "name", "dimension", name=op.f("uq_embedding_models_provider")
        ),
    )
    op.create_table(
        "kev_entries",
        sa.Column("cve_id", sa.String(length=24), nullable=False),
        sa.Column("vendor_project", sa.String(length=300), nullable=False),
        sa.Column("product", sa.String(length=300), nullable=False),
        sa.Column("vulnerability_name", sa.Text(), nullable=False),
        sa.Column("short_description", sa.Text(), nullable=False),
        sa.Column("required_action", sa.Text(), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("date_added", sa.Date(), nullable=False),
        sa.Column("due_date", sa.Date(), nullable=True),
        sa.Column("known_ransomware_use", sa.String(length=16), nullable=False),
        sa.Column("cwes", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("catalog_version", sa.String(length=32), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'", name=op.f("ck_kev_entries_cve_id_format")
        ),
        sa.PrimaryKeyConstraint("cve_id", name=op.f("pk_kev_entries")),
    )
    op.create_index("ix_kev_entries_date_added", "kev_entries", ["date_added"], unique=False)
    op.create_index(
        "ix_kev_entries_vendor_lower",
        "kev_entries",
        [sa.literal_column("lower(vendor_project)")],
        unique=False,
    )
    op.create_table(
        "sources",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("code", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("url", sa.String(length=500), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("watermark", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_sources")),
        sa.UniqueConstraint("code", name=op.f("uq_sources_code")),
    )
    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("cve_id", sa.String(length=24), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("title", sa.Text(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("assigner", sa.String(length=100), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source_updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("severity", sa.String(length=10), nullable=True),
        sa.Column("cvss_base_score", sa.Float(), nullable=True),
        sa.Column("cvss_version", sa.String(length=8), nullable=True),
        sa.Column("cvss_provider", sa.String(length=100), nullable=True),
        sa.Column(
            "search_tsv",
            postgresql.TSVECTOR(),
            sa.Computed(
                "setweight(to_tsvector('english', coalesce(cve_id, '')), 'A') || setweight(to_tsvector('english', coalesce(title, '')), 'A') || setweight(to_tsvector('english', coalesce(description, '')), 'B')",
                persisted=True,
            ),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'", name=op.f("ck_vulnerabilities_cve_id_format")
        ),
        sa.CheckConstraint(
            "severity IS NULL OR severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE')",
            name=op.f("ck_vulnerabilities_severity_valid"),
        ),
        sa.CheckConstraint(
            "cvss_base_score IS NULL OR (cvss_base_score >= 0 AND cvss_base_score <= 10)",
            name=op.f("ck_vulnerabilities_cvss_range"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_vulnerabilities")),
        sa.UniqueConstraint("cve_id", name=op.f("uq_vulnerabilities_cve_id")),
    )
    op.create_index(
        "ix_vulnerabilities_cvss_base_score", "vulnerabilities", ["cvss_base_score"], unique=False
    )
    op.create_index(
        "ix_vulnerabilities_published_at", "vulnerabilities", ["published_at"], unique=False
    )
    op.create_index(
        "ix_vulnerabilities_search_tsv",
        "vulnerabilities",
        ["search_tsv"],
        unique=False,
        postgresql_using="gin",
    )
    op.create_index("ix_vulnerabilities_severity", "vulnerabilities", ["severity"], unique=False)
    op.create_table(
        "affected_products",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("vulnerability_id", sa.BigInteger(), nullable=False),
        sa.Column("ingest_source", sa.String(length=32), nullable=False),
        sa.Column("provider", sa.String(length=100), nullable=False),
        sa.Column("vendor", sa.String(length=300), nullable=True),
        sa.Column("product", sa.String(length=300), nullable=True),
        sa.Column("package_name", sa.String(length=300), nullable=True),
        sa.Column("collection_url", sa.String(length=500), nullable=True),
        sa.Column("ecosystem", sa.String(length=32), nullable=True),
        sa.Column("default_status", sa.String(length=16), nullable=True),
        sa.Column("cpes", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("versions", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.ForeignKeyConstraint(
            ["vulnerability_id"],
            ["vulnerabilities.id"],
            name=op.f("fk_affected_products_vulnerability_id_vulnerabilities"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_affected_products")),
    )
    op.create_index(
        "ix_affected_products_package_lower",
        "affected_products",
        [sa.literal_column("lower(package_name)")],
        unique=False,
    )
    op.create_index(
        "ix_affected_products_product_lower",
        "affected_products",
        [sa.literal_column("lower(product)")],
        unique=False,
    )
    op.create_index(
        "ix_affected_products_vendor_lower",
        "affected_products",
        [sa.literal_column("lower(vendor)")],
        unique=False,
    )
    op.create_index(
        op.f("ix_affected_products_vulnerability_id"),
        "affected_products",
        ["vulnerability_id"],
        unique=False,
    )
    op.create_table(
        "capec_attack_mappings",
        sa.Column("capec_id", sa.String(length=16), nullable=False),
        sa.Column("technique_id", sa.String(length=16), nullable=False),
        sa.ForeignKeyConstraint(
            ["capec_id"],
            ["capec_patterns.capec_id"],
            name=op.f("fk_capec_attack_mappings_capec_id_capec_patterns"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("capec_id", "technique_id", name=op.f("pk_capec_attack_mappings")),
    )
    op.create_index(
        op.f("ix_capec_attack_mappings_technique_id"),
        "capec_attack_mappings",
        ["technique_id"],
        unique=False,
    )
    op.create_table(
        "capec_cwe_mappings",
        sa.Column("capec_id", sa.String(length=16), nullable=False),
        sa.Column("cwe_id", sa.String(length=16), nullable=False),
        sa.ForeignKeyConstraint(
            ["capec_id"],
            ["capec_patterns.capec_id"],
            name=op.f("fk_capec_cwe_mappings_capec_id_capec_patterns"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("capec_id", "cwe_id", name=op.f("pk_capec_cwe_mappings")),
    )
    op.create_index(
        op.f("ix_capec_cwe_mappings_cwe_id"), "capec_cwe_mappings", ["cwe_id"], unique=False
    )
    op.create_table(
        "chunk_embeddings",
        sa.Column("chunk_id", sa.BigInteger(), nullable=False),
        sa.Column("model_id", sa.Integer(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("embedding", pgvector.sqlalchemy.vector.VECTOR(dim=768), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["chunk_id"],
            ["document_chunks.id"],
            name=op.f("fk_chunk_embeddings_chunk_id_document_chunks"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["model_id"],
            ["embedding_models.id"],
            name=op.f("fk_chunk_embeddings_model_id_embedding_models"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("chunk_id", "model_id", name=op.f("pk_chunk_embeddings")),
    )
    op.create_index(
        "ix_chunk_embeddings_hnsw",
        "chunk_embeddings",
        ["embedding"],
        unique=False,
        postgresql_using="hnsw",
        postgresql_ops={"embedding": "vector_cosine_ops"},
    )
    op.create_table(
        "cvss_metrics",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("vulnerability_id", sa.BigInteger(), nullable=False),
        sa.Column("ingest_source", sa.String(length=32), nullable=False),
        sa.Column("provider", sa.String(length=100), nullable=False),
        sa.Column("version", sa.String(length=8), nullable=False),
        sa.Column("vector", sa.String(length=200), nullable=True),
        sa.Column("base_score", sa.Float(), nullable=False),
        sa.Column("base_severity", sa.String(length=10), nullable=True),
        sa.CheckConstraint(
            "base_score >= 0 AND base_score <= 10", name=op.f("ck_cvss_metrics_score_range")
        ),
        sa.ForeignKeyConstraint(
            ["vulnerability_id"],
            ["vulnerabilities.id"],
            name=op.f("fk_cvss_metrics_vulnerability_id_vulnerabilities"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_cvss_metrics")),
        sa.UniqueConstraint(
            "vulnerability_id",
            "ingest_source",
            "provider",
            "version",
            name=op.f("uq_cvss_metrics_vulnerability_id"),
        ),
    )
    op.create_index(
        op.f("ix_cvss_metrics_vulnerability_id"), "cvss_metrics", ["vulnerability_id"], unique=False
    )
    op.create_table(
        "ingestion_jobs",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("source_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("trigger", sa.String(length=16), nullable=False),
        sa.Column("params", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("records_fetched", sa.Integer(), nullable=False),
        sa.Column("records_inserted", sa.Integer(), nullable=False),
        sa.Column("records_updated", sa.Integer(), nullable=False),
        sa.Column("records_unchanged", sa.Integer(), nullable=False),
        sa.Column("records_failed", sa.Integer(), nullable=False),
        sa.Column("error_summary", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'succeeded', 'partial', 'failed')",
            name=op.f("ck_ingestion_jobs_status_valid"),
        ),
        sa.ForeignKeyConstraint(
            ["source_id"], ["sources.id"], name=op.f("fk_ingestion_jobs_source_id_sources")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ingestion_jobs")),
    )
    op.create_index(
        "ix_ingestion_jobs_source_started",
        "ingestion_jobs",
        ["source_id", "started_at"],
        unique=False,
    )
    op.create_index(
        "uq_ingestion_jobs_one_active_per_source",
        "ingestion_jobs",
        ["source_id"],
        unique=True,
        postgresql_where=sa.text("status IN ('queued', 'running')"),
    )
    op.create_table(
        "vuln_references",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("vulnerability_id", sa.BigInteger(), nullable=False),
        sa.Column("url", sa.String(length=2000), nullable=False),
        sa.Column("ingest_source", sa.String(length=32), nullable=False),
        sa.Column("name", sa.Text(), nullable=True),
        sa.Column("tags", postgresql.ARRAY(sa.String()), nullable=False),
        sa.ForeignKeyConstraint(
            ["vulnerability_id"],
            ["vulnerabilities.id"],
            name=op.f("fk_vuln_references_vulnerability_id_vulnerabilities"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_vuln_references")),
        sa.UniqueConstraint(
            "vulnerability_id", "url", name=op.f("uq_vuln_references_vulnerability_id")
        ),
    )
    op.create_table(
        "vulnerability_cwes",
        sa.Column("vulnerability_id", sa.BigInteger(), nullable=False),
        sa.Column("cwe_id", sa.String(length=16), nullable=False),
        sa.Column("ingest_source", sa.String(length=32), nullable=False),
        sa.Column("provider", sa.String(length=100), nullable=False),
        sa.ForeignKeyConstraint(
            ["cwe_id"],
            ["cwe_entries.cwe_id"],
            name=op.f("fk_vulnerability_cwes_cwe_id_cwe_entries"),
        ),
        sa.ForeignKeyConstraint(
            ["vulnerability_id"],
            ["vulnerabilities.id"],
            name=op.f("fk_vulnerability_cwes_vulnerability_id_vulnerabilities"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "vulnerability_id",
            "cwe_id",
            "ingest_source",
            "provider",
            name=op.f("pk_vulnerability_cwes"),
        ),
    )
    op.create_index(
        op.f("ix_vulnerability_cwes_cwe_id"), "vulnerability_cwes", ["cwe_id"], unique=False
    )
    op.create_table(
        "ingestion_errors",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("job_id", sa.BigInteger(), nullable=False),
        sa.Column("record_key", sa.String(length=200), nullable=True),
        sa.Column("stage", sa.String(length=32), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["ingestion_jobs.id"],
            name=op.f("fk_ingestion_errors_job_id_ingestion_jobs"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ingestion_errors")),
    )
    op.create_index(
        op.f("ix_ingestion_errors_job_id"), "ingestion_errors", ["job_id"], unique=False
    )
    op.create_table(
        "source_records",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("source_id", sa.Integer(), nullable=False),
        sa.Column("record_key", sa.String(length=200), nullable=False),
        sa.Column("source_url", sa.String(length=1000), nullable=True),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("last_fetched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_job_id", sa.BigInteger(), nullable=True),
        sa.ForeignKeyConstraint(
            ["last_job_id"],
            ["ingestion_jobs.id"],
            name=op.f("fk_source_records_last_job_id_ingestion_jobs"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"], ["sources.id"], name=op.f("fk_source_records_source_id_sources")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_source_records")),
        sa.UniqueConstraint("source_id", "record_key", name=op.f("uq_source_records_source_id")),
    )

    sources = sa.table(
        "sources",
        sa.column("code", sa.String),
        sa.column("name", sa.String),
        sa.column("url", sa.String),
        sa.column("description", sa.Text),
    )
    op.bulk_insert(sources, SOURCES)


def downgrade() -> None:
    # The vector extension is left installed: other objects in the database may use it.
    op.drop_table("source_records")
    op.drop_index(op.f("ix_ingestion_errors_job_id"), table_name="ingestion_errors")
    op.drop_table("ingestion_errors")
    op.drop_index(op.f("ix_vulnerability_cwes_cwe_id"), table_name="vulnerability_cwes")
    op.drop_table("vulnerability_cwes")
    op.drop_table("vuln_references")
    op.drop_index(
        "uq_ingestion_jobs_one_active_per_source",
        table_name="ingestion_jobs",
        postgresql_where=sa.text("status IN ('queued', 'running')"),
    )
    op.drop_index("ix_ingestion_jobs_source_started", table_name="ingestion_jobs")
    op.drop_table("ingestion_jobs")
    op.drop_index(op.f("ix_cvss_metrics_vulnerability_id"), table_name="cvss_metrics")
    op.drop_table("cvss_metrics")
    op.drop_index(
        "ix_chunk_embeddings_hnsw",
        table_name="chunk_embeddings",
        postgresql_using="hnsw",
        postgresql_ops={"embedding": "vector_cosine_ops"},
    )
    op.drop_table("chunk_embeddings")
    op.drop_index(op.f("ix_capec_cwe_mappings_cwe_id"), table_name="capec_cwe_mappings")
    op.drop_table("capec_cwe_mappings")
    op.drop_index(op.f("ix_capec_attack_mappings_technique_id"), table_name="capec_attack_mappings")
    op.drop_table("capec_attack_mappings")
    op.drop_index(op.f("ix_affected_products_vulnerability_id"), table_name="affected_products")
    op.drop_index("ix_affected_products_vendor_lower", table_name="affected_products")
    op.drop_index("ix_affected_products_product_lower", table_name="affected_products")
    op.drop_index("ix_affected_products_package_lower", table_name="affected_products")
    op.drop_table("affected_products")
    op.drop_index("ix_vulnerabilities_severity", table_name="vulnerabilities")
    op.drop_index(
        "ix_vulnerabilities_search_tsv", table_name="vulnerabilities", postgresql_using="gin"
    )
    op.drop_index("ix_vulnerabilities_published_at", table_name="vulnerabilities")
    op.drop_index("ix_vulnerabilities_cvss_base_score", table_name="vulnerabilities")
    op.drop_table("vulnerabilities")
    op.drop_table("sources")
    op.drop_index("ix_kev_entries_vendor_lower", table_name="kev_entries")
    op.drop_index("ix_kev_entries_date_added", table_name="kev_entries")
    op.drop_table("kev_entries")
    op.drop_table("embedding_models")
    op.drop_index("ix_document_chunks_tsv", table_name="document_chunks", postgresql_using="gin")
    op.drop_index("ix_document_chunks_cve_id", table_name="document_chunks")
    op.drop_table("document_chunks")
    op.drop_table("cwe_entries")
    op.drop_table("capec_patterns")
    op.drop_index(
        "ix_attack_techniques_tactics", table_name="attack_techniques", postgresql_using="gin"
    )
    op.drop_index(
        "ix_attack_techniques_search", table_name="attack_techniques", postgresql_using="gin"
    )
    op.drop_table("attack_techniques")
