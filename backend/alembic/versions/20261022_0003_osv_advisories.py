"""Add OSV advisories and their affected packages; register the osv source.

Revision ID: 0003_osv_advisories
Revises: 0002_job_details_cvss_rank
Create Date: 2026-10-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003_osv_advisories"
down_revision: str | None = "0002_job_details_cvss_rank"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "advisories",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("details", sa.Text(), nullable=True),
        sa.Column("aliases", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("cve_ids", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=True),
        sa.Column("cvss_vectors", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("cwe_ids", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("references", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source_url", sa.String(length=500), nullable=False),
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
        sa.PrimaryKeyConstraint("id", name=op.f("pk_advisories")),
    )
    op.create_index(
        "ix_advisories_aliases", "advisories", ["aliases"], unique=False, postgresql_using="gin"
    )
    op.create_index(
        "ix_advisories_cve_ids", "advisories", ["cve_ids"], unique=False, postgresql_using="gin"
    )
    op.create_table(
        "advisory_packages",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("advisory_id", sa.String(length=100), nullable=False),
        sa.Column("ecosystem", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=300), nullable=False),
        sa.Column("normalized_name", sa.String(length=300), nullable=False),
        sa.Column("purl", sa.String(length=500), nullable=True),
        sa.Column("ranges", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("versions", postgresql.ARRAY(sa.String()), nullable=False),
        sa.ForeignKeyConstraint(
            ["advisory_id"],
            ["advisories.id"],
            name=op.f("fk_advisory_packages_advisory_id_advisories"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_advisory_packages")),
    )
    op.create_index(
        op.f("ix_advisory_packages_advisory_id"), "advisory_packages", ["advisory_id"], unique=False
    )
    op.create_index(
        "ix_advisory_packages_lookup",
        "advisory_packages",
        ["ecosystem", "normalized_name"],
        unique=False,
    )
    op.execute(
        "INSERT INTO sources (code, name, url, description) VALUES ("
        "'osv', 'OSV.dev open source vulnerability data', 'https://osv.dev', "
        "'Ecosystem-exact advisories (GitHub Security Advisories, PyPA and others) from the "
        "official OSV data exports.')"
    )


def downgrade() -> None:
    op.execute(
        "DELETE FROM ingestion_jobs WHERE source_id = (SELECT id FROM sources WHERE code = 'osv')"
    )
    op.execute(
        "DELETE FROM source_records WHERE source_id = (SELECT id FROM sources WHERE code = 'osv')"
    )
    op.execute("DELETE FROM sources WHERE code = 'osv'")
    op.drop_index("ix_advisory_packages_lookup", table_name="advisory_packages")
    op.drop_index(op.f("ix_advisory_packages_advisory_id"), table_name="advisory_packages")
    op.drop_table("advisory_packages")
    op.drop_index("ix_advisories_cve_ids", table_name="advisories", postgresql_using="gin")
    op.drop_index("ix_advisories_aliases", table_name="advisories", postgresql_using="gin")
    op.drop_table("advisories")
