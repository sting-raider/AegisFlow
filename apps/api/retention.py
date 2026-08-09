from __future__ import annotations

import os
import threading
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from apps.api.database import Repository


class RetentionWorker:
    """Runs bounded operational cleanup on a fixed schedule after the first interval."""

    def __init__(
        self,
        repository: Repository,
        *,
        days: int,
        interval_seconds: float,
        audit_days: int = 365,
    ) -> None:
        if not 1 <= days <= 3650:
            raise ValueError("retention days must be between one and 3650")
        if interval_seconds <= 0:
            raise ValueError("retention interval must be positive")
        if not days <= audit_days <= 3650:
            raise ValueError("audit retention must be at least operational retention")
        self.repository = repository
        self.days = days
        self.audit_days = audit_days
        self.interval_seconds = interval_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def run_once(self, now: datetime | None = None) -> dict[str, int]:
        current = now or datetime.now(UTC)
        if current.tzinfo is None:
            raise ValueError("retention time must be timezone-aware")
        cutoff = current.astimezone(UTC) - timedelta(days=self.days)
        audit_cutoff = current.astimezone(UTC) - timedelta(days=self.audit_days)
        try:
            counts = self.repository.cleanup_before(cutoff, audit_cutoff=audit_cutoff)
        except Exception as exc:
            try:
                self.repository.record_health_event(
                    "retention",
                    "error",
                    {
                        "error_type": type(exc).__name__,
                        "retention_days": self.days,
                        "audit_retention_days": self.audit_days,
                    },
                )
            finally:
                raise
        self.repository.record_health_event(
            "retention",
            "ok",
            {
                "retention_days": self.days,
                "audit_retention_days": self.audit_days,
                "removed": counts,
            },
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
    audit_days = max(
        days,
        _bounded_int(env, "AEGISFLOW_AUDIT_RETENTION_DAYS", 365, 1, 3650),
    )
    interval = _bounded_int(env, "AEGISFLOW_RETENTION_INTERVAL_SECONDS", 86400, 60, 604800)
    return RetentionWorker(
        repository,
        days=days,
        interval_seconds=float(interval),
        audit_days=audit_days,
    )


def _bounded_int(
    env: Mapping[str, str], name: str, default: int, minimum: int, maximum: int
) -> int:
    try:
        value = int(env.get(name, str(default)))
    except ValueError:
        return default
    return max(minimum, min(maximum, value))


def retention_status(
    worker: RetentionWorker | None,
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    if worker is None:
        env = os.environ if environment is None else environment
        if env.get("AEGISFLOW_RETENTION_EXTERNAL", "0") == "1":
            days = _bounded_int(env, "AEGISFLOW_RETENTION_DAYS", 30, 1, 3650)
            return {
                "enabled": True,
                "mode": "external",
                "days": days,
                "audit_days": max(
                    days,
                    _bounded_int(env, "AEGISFLOW_AUDIT_RETENTION_DAYS", 365, 1, 3650),
                ),
            }
        return {"enabled": False}
    return {
        "enabled": True,
        "mode": "in_process",
        "days": worker.days,
        "audit_days": worker.audit_days,
        "interval_seconds": worker.interval_seconds,
    }
