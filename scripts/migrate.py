from __future__ import annotations

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text

from apps.api.database import database_url_from_env

# Stable signed-bigint namespace for AegisFlow schema migrations. PostgreSQL session
# advisory locks serialize DDL across concurrent pod init containers without creating
# an application table before Alembic owns the schema.
_MIGRATION_LOCK_ID = 0x4145474953464C4F


def run_migrations() -> None:
    database_url = database_url_from_env()
    engine = create_engine(database_url, pool_pre_ping=True)
    try:
        if engine.dialect.name != "postgresql":
            command.upgrade(Config("alembic.ini"), "head")
            return
        with engine.connect() as connection:
            connection.execute(
                text("SELECT pg_advisory_lock(:lock_id)"),
                {"lock_id": _MIGRATION_LOCK_ID},
            )
            try:
                command.upgrade(Config("alembic.ini"), "head")
            finally:
                connection.execute(
                    text("SELECT pg_advisory_unlock(:lock_id)"),
                    {"lock_id": _MIGRATION_LOCK_ID},
                )
    finally:
        engine.dispose()


if __name__ == "__main__":
    run_migrations()
