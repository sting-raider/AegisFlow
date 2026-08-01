from __future__ import annotations

import os
import threading
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from apps.api.database import Repository


class RetentionWorker:
    """Runs bounded operational cleanup on a fixed schedule after the first interval."""

    def __init__(self, repository: Repository, *, days: int, interval_seconds: float) -> None:
        if not 1 <= days <= 3650:
            raise ValueError("retention days must be between one and 3650")
        if interval_seconds <= 0:
            raise ValueError("retention interval must be positive")
        self.repository = repository
        self.days = days
        self.interval_seconds = interval_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def run_once(self, now: datetime | None = None) -> dict[str, int]:
        current = now or datetime.now(UTC)
        if current.tzinfo is None:
            raise ValueError("retention time must be timezone-aware")
        cutoff = current.astimezone(UTC) - timedelta(days=self.days)
        try:
            counts = self.repository.cleanup_before(cutoff)
        except Exception as exc:
            try:
                self.repository.record_health_event(
                    "retention",
                    "error",
                    {"error_type": type(exc).__name__, "retention_days": self.days},
                )
            finally:
                raise
        self.repository.record_health_event(
            "retention",
            "ok",
            {"retention_days": self.days, "removed": counts},
        )
        return counts

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop,
            name="aegisflow-retention",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=min(5.0, self.interval_seconds + 0.1))

    def _loop(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            try:
                self.run_once()
            except Exception:
                # The health write above is the visible error path; keep future runs alive.
                continue


def retention_worker_from_env(
    repository: Repository, environment: Mapping[str, str] | None = None
) -> RetentionWorker | None:
    env = os.environ if environment is None else environment
    if env.get("AEGISFLOW_RETENTION_ENABLED", "1") != "1":
        return None
    days = _bounded_int(env, "AEGISFLOW_RETENTION_DAYS", 30, 1, 3650)
    interval = _bounded_int(env, "AEGISFLOW_RETENTION_INTERVAL_SECONDS", 86400, 60, 604800)
    return RetentionWorker(repository, days=days, interval_seconds=float(interval))


def _bounded_int(
    env: Mapping[str, str], name: str, default: int, minimum: int, maximum: int
) -> int:
    try:
        value = int(env.get(name, str(default)))
    except ValueError:
        return default
    return max(minimum, min(maximum, value))


def retention_status(worker: RetentionWorker | None) -> dict[str, Any]:
    if worker is None:
        return {"enabled": False}
    return {
        "enabled": True,
        "days": worker.days,
        "interval_seconds": worker.interval_seconds,
    }
