from __future__ import annotations

import pytest

from training.v2.tensors import SequenceRecord, deduplicate_records


def _record(event_id: str, port: int = 80, family: str = "benign") -> SequenceRecord:
    return {
        "event_id": event_id, "scenario": "fixture", "family": family,
        "binary_label": "benign" if family == "benign" else "malicious",
        "detailed_label": "-", "seq_sizes": [60., 60.], "seq_directions": [1, -1],
        "seq_iats_ms": [0., 1.], "total_packets": 2, "duration_ms": 1.,
        "protocol": "TCP", "tcp_syn_count": 1, "tcp_ack_count": 1,
        "tcp_fin_count": 0, "tcp_rst_count": 0, "tcp_psh_count": 0,
        "bytes_forward": 60, "bytes_reverse": 60, "packets_forward": 1,
        "packets_reverse": 1, "src_port": 12345, "dst_port": port,
        "ip_version": 4, "observability": "MEDIUM",
    }


def test_deduplication_preserves_distinct_model_input_service_features() -> None:
    records = [_record("web", 80), _record("dns", 53)]
    assert len(deduplicate_records(records)) == 2


def test_deduplication_rejects_conflicting_labels_on_identical_model_inputs() -> None:
    with pytest.raises(ValueError, match="conflicting labels"):
        deduplicate_records([_record("benign"), _record("attack", family="ddos")])


def test_deduplication_still_removes_label_consistent_repeated_inputs() -> None:
    assert len(deduplicate_records([_record("first"), _record("second")])) == 1
