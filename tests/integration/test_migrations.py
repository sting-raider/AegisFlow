from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect

from scripts import migrate
from scripts.migrate import run_migrations


def test_migrations_use_database_url_secret_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    database = tmp_path / "migrated.db"
    database_url = f"sqlite:///{database.as_posix()}"
    secret = tmp_path / "database-url"
    secret.write_text(f"{database_url}\n", encoding="utf-8")
    monkeypatch.delenv("AEGISFLOW_DATABASE_URL", raising=False)
    monkeypatch.setenv("AEGISFLOW_DATABASE_URL_FILE", str(secret))

    run_migrations()

    engine = create_engine(database_url)
    try:
        tables = set(inspect(engine).get_table_names())
    finally:
        engine.dispose()
    assert {"model_candidates", "model_reviews", "audit_log"} <= tables


def test_postgres_migrations_hold_advisory_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class FakeConnection:
        def __enter__(self) -> FakeConnection:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def execute(self, statement: object, _parameters: object) -> None:
            events.append("unlock" if "unlock" in str(statement) else "lock")

    class FakeEngine:
        dialect = type("Dialect", (), {"name": "postgresql"})()

        def connect(self) -> FakeConnection:
            return FakeConnection()

        def dispose(self) -> None:
            events.append("dispose")

    monkeypatch.setattr(migrate, "database_url_from_env", lambda: "postgresql://redacted")
    monkeypatch.setattr(migrate, "create_engine", lambda *_args, **_kwargs: FakeEngine())
    monkeypatch.setattr(
        migrate.command,
        "upgrade",
        lambda *_args, **_kwargs: events.append("upgrade"),
    )

    migrate.run_migrations()

    assert events == ["lock", "upgrade", "unlock", "dispose"]
