from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import numpy as np
import pytest
import torch

from training.v2.provenance import read_object
from training.v2.registered_family import (
    evaluate_scores,
    load_registration,
    make_partitions,
    run_rotation,
    validate_model_inputs,
    verdicts,
)
from training.v2.tensors import SequenceRecord, V2Dataset

ROOT = Path(__file__).resolve().parents[2]
CUTS = {"known_direct": 0.9, "ood_direct": 9.0, "known_review": 0.7, "ood_review": 7.0}


def test_registered_four_verdict_precedence_and_exact_cut() -> None:
    result = verdicts(np.array([0.9, 0.2, 0.7, 0.1]), np.array([10, 9, 0, 0]), CUTS)
    assert result.tolist() == ["known_attack", "suspicious_unknown", "needs_review", "benign"]


def test_unknown_recall_does_not_count_known_channel_and_review_is_separate() -> None:
    result = evaluate_scores(
        np.array([0.95, 0.2, 0.7, 0.1]),
        np.array([10, 10, 0, 0]),
        np.array([1, 1, 0, 0]),
        CUTS,
    )
    assert result["attack"]["direct_suspicious_unknown"]["rate"] == 0.5
    assert result["attack"]["direct_detection"]["rate"] == 1.0
    assert result["benign"]["direct_union_fpr"]["rate"] == 0.0
    assert result["benign"]["review_inclusive_rate"]["rate"] == 0.5
    assert result["benign"]["direct_union_fpr"]["wilson_95"][1] > 0.5


def test_registration_is_bound_and_rejects_changed_budget(tmp_path: Path) -> None:
    assert load_registration(ROOT)["splits"]["expected_rotations"] == 6
    source = "configs/research-v2/registered/DEV2-FAMILY-002.json"
    destination = tmp_path / source
    destination.parent.mkdir(parents=True)
    config = read_object(ROOT / source)
    config["calibration"]["direct_fpr_budget_per_channel"] = 0.5
    import json

    destination.write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(ValueError, match="registration"):
        load_registration(tmp_path)


@pytest.mark.parametrize("scores,distances", [([np.nan], [0]), ([0], [np.inf]), ([2], [0])])
def test_invalid_scores_are_errors(scores: list[float], distances: list[float]) -> None:
    with pytest.raises(ValueError, match="scores"):
        verdicts(np.array(scores), np.array(distances), CUTS)


def test_float32_preprocessed_aliases_across_partitions_fail_closed() -> None:
    base = V2Dataset(
        sequence=np.zeros((1, 20, 4), dtype=np.float32),
        mask=np.ones((1, 20), dtype=np.float32),
        state=np.zeros((1, 8)),
        aggregate=np.array([[1.0]], dtype=np.float64),
        binary_label=np.array([0]),
        family=["benign"],
        scenario=["a"],
        observability=["LOW"],
        event_ids=["a"],
    )
    other = deepcopy(base)
    other.aggregate[0, 0] += 1e-10
    with pytest.raises(ValueError, match="model input"):
        validate_model_inputs({"fit": base, "test": other}, np.zeros(1), np.ones(1))


def fixture_records() -> list[SequenceRecord]:
    records: list[SequenceRecord] = []
    for scenario, families in (
        ("CTU-IoT-Malware-Capture-34-1", ["benign", "c_and_c", "ddos", "port_scan"]),
        ("CTU-IoT-Malware-Capture-8-1", ["c_and_c"]),
        ("CTU-IoT-Malware-Capture-42-1", ["benign"]),
        ("CTU-Honeypot-Capture-4-1", ["benign"]),
        ("CTU-Honeypot-Capture-5-1", ["benign"]),
    ):
        for family in families:
            for _ in range(3):
                n = len(records) + 1
                records.append(
                    {
                        "event_id": f"fixture-{n}",
                        "scenario": scenario,
                        "family": family,
                        "binary_label": "benign" if family == "benign" else "malicious",
                        "detailed_label": "-",
                        "seq_sizes": [float(60 + n), 60.0],
                        "seq_directions": [1, -1],
                        "seq_iats_ms": [0.0, float(n)],
                        "total_packets": 2,
                        "duration_ms": float(n),
                        "protocol": "TCP",
                        "tcp_syn_count": 1,
                        "tcp_ack_count": 1,
                        "tcp_fin_count": 0,
                        "tcp_rst_count": 0,
                        "tcp_psh_count": 0,
                        "bytes_forward": 60 + n,
                        "bytes_reverse": 60,
                        "packets_forward": 1,
                        "packets_reverse": 1,
                        "src_port": 12345,
                        "dst_port": 80,
                        "ip_version": 4,
                        "observability": "MEDIUM",
                    }
                )
    return records


def test_all_six_registered_partitions_exclude_families_and_both_sites() -> None:
    config = load_registration(ROOT)
    for family in config["splits"]["held_family_attack_scenarios"]:
        for orientation in config["splits"]["site_orientations"]:
            partitions = make_partitions(fixture_records(), config, family, orientation)
            assert all(r["family"] != family for r in partitions["fit"])
            assert not {r["scenario"] for r in partitions["fit"]} & set(orientation.values())


def test_reduced_fixture_executes_training_metrics_cost_and_numeric_artifact(
    tmp_path: Path,
) -> None:
    config = load_registration(ROOT)
    # A unit fixture, not a registered experiment: the public entry point only
    # accepts the hash-bound configuration and cannot apply these reductions.
    config["model"]["epochs"] = 2
    config["measurement"]["warmup_calls_per_batch_size"] = 1
    config["measurement"]["measured_calls_per_batch_size"] = 2
    previous_threads = torch.get_num_threads()
    torch.set_num_threads(1)
    try:
        result = run_rotation(
            fixture_records(),
            config,
            "c_and_c",
            config["splits"]["site_orientations"][0],
            tmp_path,
            "fixture",
        )
    finally:
        torch.set_num_threads(previous_threads)
    assert result["test"]["attack"]["rows"] == 6
    assert result["calibration"]["benign"]["direct_union_fpr"]["rate"] <= 0.01
    assert result["fit_wall_seconds"] > 0
    assert result["memory"]["rss_after_bytes"] > 0
    assert len(result["inference"]) == 2
    assert len(result["artifact"]["sha256"]) == 64
    with np.load(tmp_path / "fixture.npz", allow_pickle=False) as artifact:
        assert artifact["preprocessing_center"].shape == (24,)
        assert artifact["ood_inverse"].shape == (48, 48)
    assert "event_ids_sha256" in result["partition_provenance"]["held_attack"]


def test_existing_output_refused_before_code_or_data_access(tmp_path: Path) -> None:
    from training.v2.registered_family import run

    with pytest.raises(FileExistsError, match="overwrite"):
        run(tmp_path / "missing", tmp_path / "missing-pcaps", tmp_path)
