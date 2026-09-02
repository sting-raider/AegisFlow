from __future__ import annotations

import hashlib
import json
from pathlib import Path

from training.v2.tensors import AGGREGATE_FEATURE_NAMES


def test_corrected_family_registration_binds_protocol_preparation_and_six_rotations() -> None:
    root = Path(__file__).resolve().parents[2]
    registration = json.loads(
        (root / "configs/research-v2/registered/DEV2-FAMILY-002.json").read_text(encoding="utf-8")
    )
    assert registration["status"] == "registered_not_run"
    assert registration["permitted_use"] == "development_only"
    assert registration["candidate_promotion_authorized"] is False
    for name in ("protocol", "prepared_manifest"):
        binding = registration[name]
        content = (root / binding["path"]).read_bytes().replace(b"\r\n", b"\n")
        assert hashlib.sha256(content).hexdigest() == binding["sha256"]
    assert registration["representation"]["aggregate_features"] == list(AGGREGATE_FEATURE_NAMES)
    splits = registration["splits"]
    assert len(splits["held_family_attack_scenarios"]) * len(splits["site_orientations"]) == 6
    for orientation in splits["site_orientations"]:
        assert orientation["calibration"] != orientation["benign_test"]
        assert not set(orientation.values()) & set(splits["fit_source_scenarios"])
    calibration = registration["calibration"]
    assert 2 * calibration["direct_fpr_budget_per_channel"] == 0.01
    assert 2 * calibration["review_inclusive_budget_per_channel"] == 0.05
    manifest = json.loads((root / registration["prepared_manifest"]["path"]).read_text())
    assert len(manifest["scenarios"]) == 6
    assert sum(scenario["records"] for scenario in manifest["scenarios"]) == 7145


def test_origin_registration_binds_fixed_models_independent_sites_and_complete_matrix() -> None:
    root = Path(__file__).resolve().parents[2]
    config = json.loads(
        (root / "configs/research-v2/registered/DEV2-ORIGIN-002.json").read_text(encoding="utf-8")
    )
    for name in ("protocol", "preparation", "encoder_report"):
        binding = config[name]
        content = (root / binding["path"]).read_bytes().replace(b"\r\n", b"\n")
        assert hashlib.sha256(content).hexdigest() == binding["sha256"]
    assert sum(config["input"]["expected_counts"]) == 392
    assert len(config["views"]) == 8
    assert len(config["transforms"]) == 4
    assert config["validation"]["folds"] == 5
    assert config["validation"]["block_threshold"] == 0.90
    report = json.loads((root / config["encoder_report"]["path"]).read_text())
    for rotation in report["rotations"]:
        assert not set(config["input"]["scenarios"]) & set(
            rotation["partition_provenance"]["fit"]["scenarios"]
        )
