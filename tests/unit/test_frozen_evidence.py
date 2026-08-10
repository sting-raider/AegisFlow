from __future__ import annotations

import json
from pathlib import Path

import pytest

from training.evidence.frozen import (
    FrozenEvidenceError,
    evaluation_config_sha256,
    sha256_file,
    verify_frozen_evidence,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MANIFEST = REPOSITORY_ROOT / "configs/evaluation/frozen-evidence-v1.json"


def test_repository_frozen_evidence_is_intact() -> None:
    summary = verify_frozen_evidence(MANIFEST, repository_root=REPOSITORY_ROOT)

    assert summary.reports_verified == 4
    assert summary.source_fingerprints_verified == 8
    assert summary.permitted_use == "final_acceptance_only"


def _fixture(tmp_path: Path) -> tuple[Path, Path]:
    report = {
        "schema_version": "1.1.0",
        "dataset": "development-fixture",
        "fingerprint": "dataset-fingerprint",
        "evaluation_bundle": {"model_name": "locked", "version": "1"},
        "evaluation": {
            "feature_order": ["duration_ms"],
            "fit_manifest": {"fit": "fresh-development-only"},
            "harness": "exact deployed hybrid pipeline",
            "seed": 431,
            "shared_inference_path": True,
            "train_rows": 2,
            "test_rows": 1,
            "training_dataset": "development-fixture",
            "training_fingerprint": "train-fingerprint",
            "testing_dataset": "frozen-fixture",
            "testing_fingerprint": "test-fingerprint",
            "training_classes": ["benign", "known"],
            "unknown_test_families": ["held"],
            "readiness_gate": {
                "automatic_promotion_allowed": False,
                "criteria": {
                    "benign_false_positive_rate": {
                        "operator": "<=",
                        "threshold": 0.01,
                        "value": 0.5,
                        "status": "fail",
                    }
                },
                "policy": "final evidence cannot promote automatically",
                "status": "fail",
            },
        },
        "provenance": {
            "filename": "frozen.csv",
            "size_bytes": 123,
            "sha256": "a" * 64,
        },
    }
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    manifest = {
        "schema_version": "1.0.0",
        "policy": {
            "permitted_use": "final_acceptance_only",
            "development_use_allowed": False,
            "candidate_lock_required_before_final_run": True,
            "maximum_final_runs_per_locked_candidate": 1,
        },
        "reports": [
            {
                "id": "fixture",
                "path": "report.json",
                "report_sha256": sha256_file(report_path),
                "evaluation_config_sha256": evaluation_config_sha256(report),
                "published_commit": "b" * 40,
                "published_at": "2026-08-01T00:00:00Z",
                "permitted_use": "final_acceptance_only",
                "source_files": [
                    {"filename": "frozen.csv", "size_bytes": 123, "sha256": "a" * 64}
                ],
            }
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return manifest_path, report_path


def test_report_tampering_fails_closed(tmp_path: Path) -> None:
    manifest_path, report_path = _fixture(tmp_path)
    report_path.write_text(report_path.read_text(encoding="utf-8") + " ", encoding="utf-8")

    with pytest.raises(FrozenEvidenceError, match="report hash mismatch"):
        verify_frozen_evidence(manifest_path, repository_root=tmp_path)


def test_configuration_tampering_is_detected_even_with_updated_report_hash(
    tmp_path: Path,
) -> None:
    manifest_path, report_path = _fixture(tmp_path)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["evaluation"]["seed"] = 999
    report_path.write_text(json.dumps(report), encoding="utf-8")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["reports"][0]["report_sha256"] = sha256_file(report_path)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(FrozenEvidenceError, match="evaluation config hash mismatch"):
        verify_frozen_evidence(manifest_path, repository_root=tmp_path)


def test_development_use_policy_is_rejected(tmp_path: Path) -> None:
    manifest_path, _ = _fixture(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["policy"]["development_use_allowed"] = True
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(FrozenEvidenceError, match="development_use_allowed"):
        verify_frozen_evidence(manifest_path, repository_root=tmp_path)
