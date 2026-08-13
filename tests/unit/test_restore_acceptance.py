from __future__ import annotations

import pytest

from scripts.accept_restore import RestoreAcceptanceError, _parse_prefixed, compare_snapshots
from scripts.restore_fixture import SNAPSHOT_PREFIX


def _snapshot(*, alert_count: int = 2, digest: str = "a" * 64) -> dict[str, object]:
    return {
        "tables": {
            "alerts": {
                "count": alert_count,
                "identity_columns": ["id"],
                "identity_sha256": digest,
            },
            "flows": {
                "count": 3,
                "identity_columns": ["event_id"],
                "identity_sha256": "b" * 64,
            },
        }
    }


def test_restore_snapshot_passes_only_with_same_counts_and_identities() -> None:
    assert compare_snapshots(_snapshot(), _snapshot()) == []


def test_restore_snapshot_fails_on_row_loss() -> None:
    failures = compare_snapshots(_snapshot(), _snapshot(alert_count=1))
    assert failures == ["table alerts row count differs after restore"]


def test_restore_snapshot_fails_on_identity_change() -> None:
    failures = compare_snapshots(_snapshot(), _snapshot(digest="c" * 64))
    assert failures == ["table alerts primary identities differ after restore"]


def test_restore_snapshot_fails_on_missing_table() -> None:
    after = _snapshot()
    tables = after["tables"]
    assert isinstance(tables, dict)
    tables.pop("alerts")
    failures = compare_snapshots(_snapshot(), after)
    assert failures == [
        "restored table set differs from backup source",
        "table alerts snapshot is missing",
    ]


def test_restore_helper_parses_only_explicit_result_marker() -> None:
    output = "startup log\n" + SNAPSHOT_PREFIX + '{"tables":{}}\n'
    assert _parse_prefixed(output, SNAPSHOT_PREFIX) == {"tables": {}}
    with pytest.raises(RestoreAcceptanceError, match="result marker"):
        _parse_prefixed("unrelated log", SNAPSHOT_PREFIX)
