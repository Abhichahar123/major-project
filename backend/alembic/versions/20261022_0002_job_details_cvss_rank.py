"""Add ingestion job details and CVSS provider rank.

Revision ID: 0002_job_details_cvss_rank
Revises: 0001_initial
Create Date: 2026-10-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002_job_details_cvss_rank"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("ingestion_jobs", sa.Column("details", postgresql.JSONB(), nullable=True))
    op.add_column(
        "cvss_metrics",
        sa.Column("provider_rank", sa.SmallInteger(), server_default="3", nullable=False),
    )


def downgrade() -> None:
    op.drop_column("cvss_metrics", "provider_rank")
    op.drop_column("ingestion_jobs", "details")
