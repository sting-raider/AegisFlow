from __future__ import annotations

from copy import deepcopy

import numpy as np
import pytest

from packages.features.research import TEMPORAL_FEATURE_NAMES
from training.v2.registered_context import VIEWS, ContextRow, context_views
from training.v2.tensors import SequenceRecord


def _record(index: int, scenario: str = "scenario-a") -> SequenceRecord:
    return {
        "event_id": f"event-{index}",
        "scenario": scenario,
        "family": "benign" if index % 2 == 0 else "c_and_c",
        "detailed_label": "-",
        "binary_label": "benign" if index % 2 == 0 else "malicious",
        "seq_sizes": [60.0],
        "seq_directions": [1],
        "seq_iats_ms": [0.0],
        "total_packets": index + 1,
        "duration_ms": float(index + 1),
        "protocol": "TCP",
        "tcp_syn_count": 1,
        "tcp_ack_count": 0,
        "tcp_fin_count": 0,
        "tcp_rst_count": 0,
        "tcp_psh_count": 0,
        "bytes_forward": 60,
        "bytes_reverse": 0,
        "packets_forward": 1,
        "packets_reverse": 0,
        "src_port": 5000 + index,
        "dst_port": 443,
        "ip_version": 4,
        "observability": "HIGH",
    }


def _contexts(records: list[SequenceRecord]) -> dict[str, ContextRow]:
    result = {}
    for index, record in enumerate(records):
        causal = np.arange(16, dtype=np.float64) + index * 100
        terminal = causal + 10_000
        result[record["event_id"]] = ContextRow(
            scenario=record["scenario"], causal=causal, terminal=terminal
        )
    return result


def test_context_views_keep_portable_inputs_paired_and_build_fixed_controls() -> None:
    records = [_record(index) for index in range(6)]
    matrices = context_views(records, _contexts(records), role="fit", seed=20260910)

    assert tuple(matrices) == VIEWS
    assert all(matrix.shape == (6, 25) for matrix in matrices.values())
    for matrix in matrices.values():
        np.testing.assert_array_equal(matrix[:, :9], matrices["causal_context"][:, :9])
    np.testing.assert_array_equal(
        matrices["no_context"][:, 9 + TEMPORAL_FEATURE_NAMES.index("temporal_cold_start")],
        np.ones(6),
    )
    assert np.count_nonzero(matrices["no_context"][:, 9:]) == 6
    np.testing.assert_array_equal(
        matrices["non_causal_reference"][:, 9:],
        matrices["causal_context"][:, 9:] + 10_000,
    )


def test_shuffle_is_deterministic_marginal_preserving_and_scenario_local() -> None:
    records = [
        *[_record(index, "scenario-a") for index in range(6)],
        *[_record(index + 10, "scenario-b") for index in range(4)],
    ]
    contexts = _contexts(records)
    first = context_views(records, contexts, role="fit", seed=20260910)
    second = context_views(records, contexts, role="fit", seed=20260910)

    np.testing.assert_array_equal(first["shuffled_context"], second["shuffled_context"])
    for scenario in ("scenario-a", "scenario-b"):
        indices = [i for i, record in enumerate(records) if record["scenario"] == scenario]
        causal_rows = sorted(map(tuple, first["causal_context"][indices, 9:]))
        shuffled_rows = sorted(map(tuple, first["shuffled_context"][indices, 9:]))
        assert shuffled_rows == causal_rows
    assert not np.array_equal(
        first["causal_context"][:, 9:], first["shuffled_context"][:, 9:]
    )


def test_shuffle_assignment_is_stable_when_input_order_changes() -> None:
    records = [_record(index) for index in range(6)]
    contexts = _contexts(records)
    forward = context_views(records, contexts, role="target", seed=20260910)
    reversed_records = list(reversed(records))
    reverse = context_views(reversed_records, contexts, role="target", seed=20260910)
    by_id = {
        record["event_id"]: reverse["shuffled_context"][index, 9:]
        for index, record in enumerate(reversed_records)
    }
    for index, record in enumerate(records):
        np.testing.assert_array_equal(
            forward["shuffled_context"][index, 9:], by_id[record["event_id"]]
        )


def test_context_views_reject_missing_duplicate_and_scenario_mismatch() -> None:
    records = [_record(index) for index in range(3)]
    contexts = _contexts(records)
    with pytest.raises(ValueError, match="missing context row"):
        context_views(
            records,
            {records[0]["event_id"]: contexts[records[0]["event_id"]]},
            role="fit",
            seed=1,
        )

    duplicates = [records[0], deepcopy(records[0])]
    with pytest.raises(ValueError, match="unique event IDs"):
        context_views(duplicates, contexts, role="fit", seed=1)

    mismatched = dict(contexts)
    mismatched[records[0]["event_id"]] = ContextRow(
        scenario="wrong", causal=np.zeros(16), terminal=np.zeros(16)
    )
    with pytest.raises(ValueError, match="scenario mismatch"):
        context_views(records, mismatched, role="fit", seed=1)
