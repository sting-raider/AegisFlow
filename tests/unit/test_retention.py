from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import pytest

from apps.api.database import Repository
from apps.api.retention import RetentionWorker, retention_status, retention_worker_from_env


class RecordingRepository:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.cutoffs: list[datetime] = []
        self.health: list[tuple[str, str, dict[str, Any]]] = []

    def cleanup_before(self, cutoff: datetime) -> dict[str, int]:
        self.cutoffs.append(cutoff)
        if self.fail:
            raise RuntimeError("database unavailable")
        return {"flows": 2}

    def record_health_event(
        self, service: str, status: str, details: dict[str, Any] | None = None
    ) -> str:
        self.health.append((service, status, details or {}))
        return "health-1"


def test_retention_run_records_cutoff_and_visible_success() -> None:
    repository = RecordingRepository()
    worker = RetentionWorker(cast(Repository, repository), days=30, interval_seconds=60)

    counts = worker.run_once(datetime(2026, 8, 1, tzinfo=UTC))

    assert counts == {"flows": 2}
    assert repository.cutoffs == [datetime(2026, 7, 2, tzinfo=UTC)]
    assert repository.health == [
        ("retention", "ok", {"retention_days": 30, "removed": {"flows": 2}})
    ]


def test_retention_failure_is_visible_and_reraised() -> None:
    repository = RecordingRepository(fail=True)
    worker = RetentionWorker(cast(Repository, repository), days=7, interval_seconds=60)

    with pytest.raises(RuntimeError, match="database unavailable"):
        worker.run_once(datetime(2026, 8, 1, tzinfo=UTC))

    assert repository.health == [
        ("retention", "error", {"error_type": "RuntimeError", "retention_days": 7})
    ]


def test_retention_environment_is_bounded_and_can_be_disabled() -> None:
    repository = RecordingRepository()
    assert retention_worker_from_env(
        cast(Repository, repository), {"AEGISFLOW_RETENTION_ENABLED": "0"}
    ) is None

    worker = retention_worker_from_env(
        cast(Repository, repository),
        {
            "AEGISFLOW_RETENTION_DAYS": "99999",
            "AEGISFLOW_RETENTION_INTERVAL_SECONDS": "1",
        },
    )
    assert worker is not None
    assert retention_status(worker) == {
        "enabled": True,
        "days": 3650,
        "interval_seconds": 60.0,
    }
