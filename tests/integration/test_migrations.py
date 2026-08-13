from __future__ import annotations

import json
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config

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

    engine = sa.create_engine(database_url)
    try:
        tables = set(sa.inspect(engine).get_table_names())
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


def test_failed_postgres_migration_releases_advisory_lock_and_disposes_engine(
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

    def fail_upgrade(*_args: object, **_kwargs: object) -> None:
        events.append("upgrade_failed")
        raise RuntimeError("controlled migration failure")

    monkeypatch.setattr(migrate, "database_url_from_env", lambda: "postgresql://redacted")
    monkeypatch.setattr(migrate, "create_engine", lambda *_args, **_kwargs: FakeEngine())
    monkeypatch.setattr(migrate.command, "upgrade", fail_upgrade)

    with pytest.raises(RuntimeError, match="controlled migration failure"):
        migrate.run_migrations()

    assert events == ["lock", "upgrade_failed", "unlock", "dispose"]


def test_incident_membership_migration_backfills_existing_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database_path = tmp_path / "migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    monkeypatch.setenv("AEGISFLOW_DATABASE_URL", database_url)
    config = Config("alembic.ini")
    command.upgrade(config, "0002_model_governance")

    engine = sa.create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(
            sa.text(
                "INSERT INTO sensors (id, last_seen, mode) "
                "VALUES ('sensor-1', '2026-08-13', 'demo')"
            )
        )
        connection.execute(
            sa.text(
                "INSERT INTO flows "
                "(event_id, sensor_id, timestamp_start, timestamp_end, src_ip, dst_ip, "
                "src_port, dst_port, protocol, community_flow_id, payload) VALUES "
                "('flow-1', 'sensor-1', '2026-08-13', '2026-08-13', "
                "'192.0.2.1', '192.0.2.2', 50000, 443, 'TCP', 'community-1', :payload)"
            ),
            {"payload": json.dumps({})},
        )
        connection.execute(
            sa.text(
                "INSERT INTO detection_results "
                "(event_id, flow_event_id, timestamp, verdict, severity, risk, payload) "
                "VALUES ('detection-1', 'flow-1', '2026-08-13', "
                "'suspicious_unknown', 'low', 10.0, :payload)"
            ),
            {"payload": json.dumps({})},
        )
        connection.execute(
            sa.text(
                "INSERT INTO alerts "
                "(id, detection_id, flow_event_id, created_at, verdict, severity, risk, "
                "acknowledged) VALUES ('alert-1', 'detection-1', 'flow-1', '2026-08-13', "
                "'suspicious_unknown', 'low', 10.0, 0)"
            )
        )
        connection.execute(
            sa.text(
                "INSERT INTO incidents "
                "(id, title, status, severity, source_host, created_at, updated_at, "
                "alert_ids, grouping_reasons) VALUES "
                "('incident-1', 'test', 'open', 'low', '192.0.2.1', '2026-08-13', "
                "'2026-08-13', :alert_ids, :reasons)"
            ),
            {
                "alert_ids": json.dumps(["alert-1"]),
                "reasons": json.dumps(["initial alert"]),
            },
        )

    command.upgrade(config, "head")

    inspector = sa.inspect(engine)
    assert "grouping_context" in {
        item["name"] for item in inspector.get_columns("incidents")
    }
    assert "incident_alerts" in inspector.get_table_names()
    with engine.connect() as connection:
        memberships = [
            tuple(row)
            for row in connection.execute(
                sa.text("SELECT incident_id, alert_id FROM incident_alerts")
            ).all()
        ]
    engine.dispose()
    assert memberships == [("incident-1", "alert-1")]
