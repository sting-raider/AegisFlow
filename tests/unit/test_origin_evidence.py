from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from scripts.verify_registered_origin import REPORT_PATH, render_summary, validate_report, verify
from training.v2.provenance import read_object

ROOT = Path(__file__).resolve().parents[2]


def test_completed_origin_evidence_is_hash_bound() -> None:
    report = verify(ROOT)
    assert report["local_probe_artifacts"] == 123
    assert len(report["views"]) == 8
    assert (ROOT / REPORT_PATH).with_suffix(".md").read_text(encoding="utf-8") == render_summary(
        report
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "warning",
        "missing_view",
        "confusion",
        "partial_score",
        "cost",
        "raw_ids",
        "encoder_binding",
        "failed_cost",
    ],
)
def test_origin_semantic_tampering_fails_even_before_file_hash_check(mutation: str) -> None:
    report = deepcopy(read_object(ROOT / REPORT_PATH))
    first = report["views"][0]["transforms"][0]
    if mutation == "warning":
        first["origin_warning"] = False
    elif mutation == "missing_view":
        report["views"].pop()
    elif mutation == "confusion":
        first["folds"][0]["confusion_matrix"][0][0] += 1
    elif mutation == "partial_score":
        partial = report["views"][2]["transforms"][1]
        partial["status"] = "evaluated"
        partial["balanced_accuracy_mean"] = 0.99
        partial["origin_warning"] = True
    elif mutation == "cost":
        first["folds"][0]["fit_seconds"] = 0
    elif mutation == "failed_cost":
        failed = next(
            fold
            for view in report["views"]
            for entry in view["transforms"]
            for fold in entry["folds"]
            if fold["status"] == "ineligible"
        )
        failed.pop("fit_seconds")
    elif mutation == "raw_ids":
        report["event_ids"] = ["private-row"]
    elif mutation == "encoder_binding":
        report["encoder_report"]["execution_commit"] = "0" * 40
    with pytest.raises(ValueError):
        validate_report(ROOT, report)


def test_origin_missing_local_artifacts_fail_closed(tmp_path: Path) -> None:
    with pytest.raises((ValueError, FileNotFoundError)):
        verify(ROOT, artifact_directory=tmp_path)
