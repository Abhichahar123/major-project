"""Alembic environment.

The URL comes from ``DATABASE_URL`` via the application settings, so migrations use
exactly the same configuration (and validation) as the API. A URL passed with
``alembic -x database_url=...`` takes precedence, which the test suite uses.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import engine_from_config, pool

from alembic import context
from app.core.config import load_settings
from app.db import models  # noqa: F401  (registers tables on Base.metadata)
from app.db.base import Base


def _database_url() -> str:
    override = context.get_x_argument(as_dictionary=True).get("database_url")
    url = override or load_settings().database_url.get_secret_value()
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url.removeprefix("postgresql://")
    return url


# Expression indexes Alembic cannot compare reliably (it reports them as changed on every
# run). They are created by migrations; autogenerate simply ignores them.
_UNCOMPARABLE_INDEXES = frozenset({"ix_attack_techniques_search"})


def _include_object(
    obj: object, name: str | None, type_: str, reflected: bool, compare_to: object
) -> bool:
    return not (type_ == "index" and name in _UNCOMPARABLE_INDEXES)


def _include_name(name: str | None, type_: str, parent_names: object) -> bool:
    return not (type_ == "index" and name in _UNCOMPARABLE_INDEXES)


_COMPARE_OPTIONS: dict[str, Any] = {
    "compare_type": True,
    "include_object": _include_object,
    "include_name": _include_name,
}


def run_migrations_offline() -> None:
    context.configure(
        url=_database_url(),
        target_metadata=Base.metadata,
        literal_binds=True,
        **_COMPARE_OPTIONS,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        {"sqlalchemy.url": _database_url()}, prefix="sqlalchemy.", poolclass=pool.NullPool
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=Base.metadata, **_COMPARE_OPTIONS)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
