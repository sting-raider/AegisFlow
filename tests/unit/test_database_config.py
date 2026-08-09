from __future__ import annotations

from pathlib import Path

import pytest

from apps.api.database import Repository


def test_database_url_file_takes_precedence_without_exposing_secret_in_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    database = tmp_path / "secret-config.db"
    secret = tmp_path / "database-url"
    secret.write_text(f"sqlite:///{database.as_posix()}\n", encoding="utf-8")
    monkeypatch.setenv("AEGISFLOW_DATABASE_URL", "sqlite:///wrong.db")
    monkeypatch.setenv("AEGISFLOW_DATABASE_URL_FILE", str(secret))
    repository = Repository()
    try:
        repository.create_schema()
        assert database.exists()
    finally:
        repository.engine.dispose()


def test_database_url_secret_rejects_multiline_content(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    secret = tmp_path / "database-url"
    secret.write_text("sqlite:///first.db\nsqlite:///second.db", encoding="utf-8")
    monkeypatch.setenv("AEGISFLOW_DATABASE_URL_FILE", str(secret))
    with pytest.raises(ValueError, match="secret file is invalid"):
        Repository()
