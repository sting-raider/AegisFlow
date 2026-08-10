from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts.verify_research_experiments import verify_research_experiments


def _write_fixture(root: Path) -> Path:
    frozen = root / "configs/evaluation/frozen-evidence-v1.json"
    frozen.parent.mkdir(parents=True)
    frozen.write_text('{"reports": []}', encoding="utf-8")
    report = root / "docs/research/experiment.json"
    report.parent.mkdir(parents=True)
    report_payload = {
        "experiment_id": "TEST-001",
        "code_commit": "a" * 40,
        "feature_order": ["one"],
        "seed": 431,
        "sources": [
            {
                "source_id": "fresh",
                "dataset_fingerprint": "dataset-fingerprint",
                "provenance_sha256": ["b" * 64],
            }
        ],
    }
    report.write_text(json.dumps(report_payload), encoding="utf-8")
    digest = hashlib.sha256(report.read_bytes()).hexdigest()
    registry = root / "configs/research/experiments/TEST-001.json"
    registry.parent.mkdir(parents=True)
    registry.write_text(
        json.dumps(
            {
                "experiment_id": "TEST-001",
                "permitted_use": "development_only",
                "code_commit": "a" * 40,
                "feature_order": ["one"],
                "seed": 431,
                "dataset_fingerprints": {"fresh": "dataset-fingerprint"},
                "artifacts": [
                    {"path": "docs/research/experiment.json", "sha256": digest}
                ],
            }
        ),
        encoding="utf-8",
    )
    return report


def test_research_evidence_verifier_binds_artifacts_and_rejects_tampering(
    tmp_path: Path,
) -> None:
    report = _write_fixture(tmp_path)

    assert verify_research_experiments(tmp_path) == (1, 1)
    report.write_text("tampered", encoding="utf-8")
    with pytest.raises(ValueError, match="hash mismatch"):
        verify_research_experiments(tmp_path)


def test_research_evidence_verifier_rejects_per_row_predictions(tmp_path: Path) -> None:
    report = _write_fixture(tmp_path)
    payload = json.loads(report.read_text(encoding="utf-8"))
    payload["predictions"] = ["malicious"]
    report.write_text(json.dumps(payload), encoding="utf-8")
    registry = tmp_path / "configs/research/experiments/TEST-001.json"
    decoded = json.loads(registry.read_text(encoding="utf-8"))
    decoded["artifacts"][0]["sha256"] = hashlib.sha256(report.read_bytes()).hexdigest()
    registry.write_text(json.dumps(decoded), encoding="utf-8")

    with pytest.raises(ValueError, match="prohibited key"):
        verify_research_experiments(tmp_path)
