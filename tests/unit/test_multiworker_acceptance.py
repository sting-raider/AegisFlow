from __future__ import annotations

import pytest

from scripts.accept_multiworker import (
    AcceptanceFailure,
    assess_recovery,
    parse_consumers,
    persisted_count,
)


def _workload(*, flows: int = 100, detections: int = 100) -> dict[str, object]:
    return {
        "counts": {
            "planned": 100,
            "published": 100,
            "persisted_flows": flows,
            "persisted_detections": detections,
        },
        "queues": {"final_flow_depth": 0, "final_detection_depth": 0},
    }


def test_parse_consumers_requires_structured_bounded_fields() -> None:
    assert parse_consumers('[{"name":"api-one-1","pending":3,"idle":4,"inactive":5}]') == [
        {"name": "api-one-1", "pending": 3, "idle": 4, "inactive": 5}
    ]
    with pytest.raises(AcceptanceFailure, match="not valid JSON"):
        parse_consumers("not-json")


def test_persisted_count_uses_only_successful_structured_batch_events() -> None:
    logs = "\n".join(
        [
            '{"event_type":"detection_batch_persisted","published_count":25}',
            "unstructured startup log",
            '{"event_type":"database_retry_exhausted","published_count":64}',
            '{"event_type":"detection_batch_persisted","published_count":12}',
        ]
    )
    assert persisted_count(logs) == 37


def test_persisted_count_accepts_docker_stderr_log_text() -> None:
    assert persisted_count(
        '\n{"event_type":"detection_batch_persisted","published_count":25}'
    ) == 25


def test_recovery_passes_only_with_partitioning_reclaim_and_conservation() -> None:
    result = assess_recovery(
        workload=_workload(),
        initial_worker_persisted=25,
        restarted_worker_persisted=25,
        survivor_persisted=50,
        abandoned_pending=4,
        abandoned_pending_recovered=True,
    )
    assert result["passed"] is True
    assert all(result["criteria"].values())  # type: ignore[union-attr]


def test_recovery_fails_closed_on_missing_rows_and_unexercised_worker() -> None:
    result = assess_recovery(
        workload=_workload(detections=99),
        initial_worker_persisted=0,
        restarted_worker_persisted=25,
        survivor_persisted=50,
        abandoned_pending=0,
        abandoned_pending_recovered=False,
    )
    assert result["passed"] is False
    assert len(result["failures"]) == 4  # type: ignore[arg-type]
