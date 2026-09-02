from __future__ import annotations

from typing import cast

import numpy as np
import pytest
import torch

from training.v2 import run_cross_environment, run_domain_adversarial, run_site_calibration
from training.v2.partitions import assert_disjoint_partitions, assert_strict_family_rotation
from training.v2.run_held_family import run_rotation
from training.v2.tensors import SequenceRecord, V2Dataset, build_dataset


def _record(index: int, scenario: str, family: str) -> SequenceRecord:
    return cast(SequenceRecord, {
        "event_id": f"event-{index}",
        "scenario": scenario,
        "family": family,
        "binary_label": "benign" if family == "benign" else "malicious",
        "seq_sizes": [float(index)],
        "seq_directions": [1],
        "seq_iats_ms": [0.0],
        "total_packets": 1,
        "duration_ms": float(index),
        "bytes_forward": index,
        "bytes_reverse": 0,
        "protocol": "TCP",
    })


def _rotation() -> dict[str, list[SequenceRecord]]:
    return {
        "fit": [_record(1, "source", "ddos"), _record(2, "source", "benign")],
        "site_calibration": [_record(3, "site", "benign")],
        "held_attack": [_record(4, "target", "c_and_c")],
        "benign_test": [_record(5, "benign-test", "benign")],
    }


def test_strict_family_rotation_accepts_disjoint_partitions() -> None:
    assert_strict_family_rotation(**_rotation(), held_family="c_and_c")


def test_strict_family_rotation_rejects_historical_cross_capture_claim() -> None:
    rotation = _rotation()
    rotation["fit"].append(_record(6, "different-malware-capture", "c_and_c"))
    with pytest.raises(ValueError, match="held family c_and_c appears in fit"):
        assert_strict_family_rotation(**rotation, held_family="c_and_c")


def test_strict_family_rotation_rejects_reused_site_environment() -> None:
    rotation = _rotation()
    rotation["fit"].append(_record(6, "site", "benign"))
    with pytest.raises(ValueError, match="site-calibration scenarios overlap"):
        assert_strict_family_rotation(**rotation, held_family="c_and_c")


def test_strict_family_rotation_rejects_attack_calibration() -> None:
    rotation = _rotation()
    rotation["site_calibration"] = [_record(6, "site", "port_scan")]
    with pytest.raises(ValueError, match="not approved benign-only"):
        assert_strict_family_rotation(**rotation, held_family="c_and_c")


def test_strict_family_rotation_rejects_extra_test_family() -> None:
    rotation = _rotation()
    rotation["held_attack"].append(_record(6, "target", "ddos"))
    with pytest.raises(ValueError, match="another label or family"):
        assert_strict_family_rotation(**rotation, held_family="c_and_c")


@pytest.mark.parametrize("same_partition", [False, True])
def test_partitions_reject_reused_event_ids(same_partition: bool) -> None:
    first = _record(1, "source", "benign")
    second = _record(2, "target", "benign")
    second["event_id"] = first["event_id"]
    partitions = {"fit": [first, second]} if same_partition else {
        "fit": [first], "test": [second],
    }
    with pytest.raises(ValueError, match="event .* overlaps"):
        assert_disjoint_partitions(partitions)


def test_partitions_reject_same_observation_under_different_ids() -> None:
    first = _record(1, "source", "benign")
    second = first.copy()
    second["event_id"] = "different-id"
    second["scenario"] = "different-capture"
    with pytest.raises(ValueError, match="observation overlaps"):
        assert_disjoint_partitions({"fit": [first], "test": [second]})


def test_partitions_reject_empty_test_set() -> None:
    with pytest.raises(ValueError, match="partition test is empty"):
        assert_disjoint_partitions({"test": []})


@pytest.mark.parametrize("label", ["unreviewed", "", "unknown", "BENIGN"])
def test_tensor_build_never_maps_invalid_labels_to_benign(label: str) -> None:
    record = _record(1, "source", "benign")
    record["binary_label"] = label
    with pytest.raises(ValueError, match="invalid binary label"):
        build_dataset([record])


def test_tensor_build_rejects_inconsistent_family() -> None:
    record = _record(1, "source", "ddos")
    record["binary_label"] = "benign"
    with pytest.raises(ValueError, match="family/label mismatch"):
        build_dataset([record])


def test_held_family_runner_checks_partitions_before_model_construction() -> None:
    records = [
        _record(1, "fit", "benign"), _record(2, "fit", "c_and_c"),
        _record(3, "held", "c_and_c"), _record(4, "site", "benign"),
        _record(5, "benign-test", "benign"),
    ]
    with pytest.raises(ValueError, match="held family c_and_c appears in fit"):
        run_rotation(
            "invalid", {"fit"}, {"benign", "c_and_c"}, "c_and_c", {"held"},
            "site", "benign-test", records,
        )


def test_adversarial_initialization_and_training_are_repeatable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(run_domain_adversarial, "EPOCHS", 1)
    generator = np.random.default_rng(13)
    dataset = V2Dataset(
        sequence=generator.normal(size=(8, 20, 4)).astype(np.float32),
        mask=np.ones((8, 20), dtype=np.float32),
        aggregate=generator.normal(size=(8, 24)),
        state=np.zeros((8, 8)),
        binary_label=np.asarray([0., 1.] * 4),
        family=["benign", "c_and_c"] * 4,
        scenario=["a", "b"] * 4,
        observability=["HIGH"] * 8,
        event_ids=[f"test-{index}" for index in range(8)],
    )
    first = run_domain_adversarial.train_adversarial(
        train_dataset=dataset, scenario_labels=np.asarray(dataset.scenario), lambd=0.1,
    )
    torch.manual_seed(987)  # caller RNG state must not alter a seeded experiment
    second = run_domain_adversarial.train_adversarial(
        train_dataset=dataset, scenario_labels=np.asarray(dataset.scenario), lambd=0.1,
    )
    for left, right in zip(first.parameters(), second.parameters(), strict=True):
        assert torch.equal(left, right)


def test_legacy_sequence_entry_point_refuses_to_overwrite_archive() -> None:
    with pytest.raises(ValueError, match="historical sequence evidence exists"):
        run_cross_environment.main()


def test_legacy_site_entry_point_refuses_to_overwrite_archive() -> None:
    with pytest.raises(ValueError, match="historical site evidence exists"):
        run_site_calibration.main()
