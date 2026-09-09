from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import numpy as np

from training.v2.context_runner import run_case
from training.v2.registered_context import ContextRow, load_registration
from training.v2.tensors import SequenceRecord


def _record(index: int, scenario: str, malicious: bool) -> SequenceRecord:
    return {
        "event_id": f"{scenario}-{'m' if malicious else 'b'}-{index:03d}",
        "scenario": scenario,
        "family": "c_and_c" if malicious else "benign",
        "detailed_label": "malicious" if malicious else "-",
        "binary_label": "malicious" if malicious else "benign",
        "seq_sizes": [60.0 + malicious],
        "seq_directions": [1],
        "seq_iats_ms": [0.0],
        "total_packets": index + 2 + int(malicious),
        "duration_ms": float(index + 1 + 5 * int(malicious)),
        "protocol": "TCP",
        "tcp_syn_count": 1,
        "tcp_ack_count": int(not malicious),
        "tcp_fin_count": 0,
        "tcp_rst_count": int(malicious),
        "tcp_psh_count": 0,
        "bytes_forward": 80 + index + 100 * int(malicious),
        "bytes_reverse": 20,
        "packets_forward": 2 + int(malicious),
        "packets_reverse": 1,
        "src_port": 5000 + index,
        "dst_port": 443,
        "ip_version": 4,
        "observability": "HIGH",
    }


def _rows(scenario: str, count: int, *, malicious: bool) -> list[SequenceRecord]:
    return [_record(index, scenario, malicious) for index in range(count)]


def test_context_case_executes_both_sites_and_round_trips_artifact(tmp_path: Path) -> None:
    fit = [*_rows("attack-fit", 30, malicious=True), *_rows("background", 30, malicious=False)]
    target = [*_rows("target", 20, malicious=True), *_rows("target", 10, malicious=False)]
    partitions = {
        "fit": fit,
        "target": target,
        "site_calibration": _rows("site-a", 30, malicious=False),
        "benign_test": _rows("site-b", 30, malicious=False),
    }
    all_rows = [row for rows in partitions.values() for row in rows]
    rng = np.random.default_rng(20260910)
    contexts = {
        row["event_id"]: ContextRow(
            scenario=row["scenario"],
            causal=rng.normal(size=16),
            terminal=rng.normal(size=16),
        )
        for row in all_rows
    }
    config = deepcopy(load_registration(Path(__file__).resolve().parents[2]))
    config["measurement"]["warmup_calls_per_batch_size"] = 1
    config["measurement"]["measured_calls_per_batch_size"] = 2
    config["measurement"]["batch_sizes"] = [1, 8]
    output = tmp_path / "artifacts"
    output.mkdir()

    execution = run_case(
        partitions,
        contexts,
        config,
        case_id="synthetic-causal",
        target="target",
        sources=["attack-fit"],
        view="causal_context",
        output=output,
    )

    assert execution.report["status"] == "evaluated"
    assert execution.report["fit_attempted"] is True
    assert len(execution.report["site_evaluations"]) == 2
    assert len(execution.paired_signals) == 2
    assert all(len(item.target_event_ids) == 20 for item in execution.paired_signals)
    assert all(len(item.benign_event_ids) == 30 for item in execution.paired_signals)
    assert (output / execution.report["artifact"]["file"]).is_file()
