"""Migration tests: reproducible upgrade, reversible downgrade, and no model drift."""

from __future__ import annotations

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError

from app.db.base import Base
from tests.integration.conftest import alembic_config, truncate_all

pytestmark = pytest.mark.integration

EXPECTED_TABLES = {
    "sources",
    "ingestion_jobs",
    "ingestion_errors",
    "source_records",
    "vulnerabilities",
    "cvss_metrics",
    "cwe_entries",
    "vulnerability_cwes",
    "affected_products",
    "vuln_references",
    "kev_entries",
    "attack_techniques",
    "capec_patterns",
    "capec_cwe_mappings",
    "capec_attack_mappings",
    "document_chunks",
    "embedding_models",
    "chunk_embeddings",
}


def _engine(url: str):  # type: ignore[no-untyped-def]
    return create_engine(url.replace("postgresql://", "postgresql+psycopg://", 1))


def test_downgrade_then_upgrade_is_reproducible(database_url: str) -> None:
    config = alembic_config(database_url)
    command.upgrade(config, "head")
    command.downgrade(config, "base")

    engine = _engine(database_url)
    try:
        assert set(inspect(engine).get_table_names()) <= {"alembic_version"}
        command.upgrade(config, "head")
        tables = set(inspect(engine).get_table_names())
        assert EXPECTED_TABLES <= tables
        with engine.connect() as connection:
            codes = connection.execute(text("SELECT code FROM sources ORDER BY id")).scalars()
            assert list(codes) == ["kev", "cve5", "nvd", "attack", "capec", "embeddings"]
            assert connection.execute(
                text("SELECT count(*) FROM pg_extension WHERE extname = 'vector'")
            ).scalar_one() == 1
    finally:
        engine.dispose()


def test_models_match_migrated_schema(migrated_engine) -> None:  # type: ignore[no-untyped-def]
    ignored = {"ix_attack_techniques_search"}  # expression index; see alembic/env.py

    def include_object(obj, name, type_, reflected, compare_to):  # type: ignore[no-untyped-def]
        return not (type_ == "index" and name in ignored)

    def include_name(name, type_, parent_names):  # type: ignore[no-untyped-def]
        return not (type_ == "index" and name in ignored)

    with migrated_engine.connect() as connection:
        context = MigrationContext.configure(
            connection,
            opts={
                "compare_type": True,
                "include_object": include_object,
                "include_name": include_name,
            },
        )
        assert compare_metadata(context, Base.metadata) == []


def test_only_one_active_job_per_source(migrated_engine) -> None:  # type: ignore[no-untyped-def]
    truncate_all(migrated_engine)
    insert = text(
        "INSERT INTO ingestion_jobs (source_id, status, trigger, params, records_fetched, "
        "records_inserted, records_updated, records_unchanged, records_failed) "
        "VALUES (1, :status, 'test', '{}', 0, 0, 0, 0, 0)"
    )
    with migrated_engine.begin() as connection:
        connection.execute(insert, {"status": "running"})
        connection.execute(insert, {"status": "succeeded"})  # finished jobs do not conflict
    with pytest.raises(IntegrityError), migrated_engine.begin() as connection:
        connection.execute(insert, {"status": "queued"})
    truncate_all(migrated_engine)


def test_cve_id_format_is_enforced(migrated_engine) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(IntegrityError), migrated_engine.begin() as connection:
        connection.execute(
            text("INSERT INTO vulnerabilities (cve_id, state) VALUES ('not-a-cve', 'PUBLISHED')")
        )


def test_search_vector_is_generated(migrated_engine) -> None:  # type: ignore[no-untyped-def]
    truncate_all(migrated_engine)
    with migrated_engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO vulnerabilities (cve_id, state, title, description) VALUES "
                "('CVE-2021-44228', 'PUBLISHED', 'Log4Shell', 'JNDI lookup remote code execution')"
            )
        )
        hit = connection.execute(
            text(
                "SELECT cve_id FROM vulnerabilities "
                "WHERE search_tsv @@ websearch_to_tsquery('english', 'remote code execution')"
            )
        ).scalar_one()
    assert hit == "CVE-2021-44228"
    truncate_all(migrated_engine)
