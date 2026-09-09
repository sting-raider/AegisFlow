from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from scripts.verify_registered_context_result import REPORT_PATH, validate_report
from training.v2.provenance import read_object


def test_committed_context_result_is_valid_and_null() -> None:
    root = Path(__file__).resolve().parents[2]
    report = read_object(root / REPORT_PATH)

    validate_report(root, report)
    assert report["paired_analysis"]["benefit_detected"] is False
    assert report["coverage"]["evaluated_models"] == 36
    assert report["coverage"]["evaluated_site_entries"] == 72


def test_context_result_guard_rejects_paired_decision_mutation() -> None:
    root = Path(__file__).resolve().parents[2]
    report = deepcopy(read_object(root / REPORT_PATH))
    report["paired_analysis"]["benefit_detected"] = True

    with pytest.raises(ValueError, match="final paired decision changed"):
        validate_report(root, report)


def test_context_result_guard_rejects_case_identity_mutation() -> None:
    root = Path(__file__).resolve().parents[2]
    report = deepcopy(read_object(root / REPORT_PATH))
    report["cases"][0]["view"] = "no_context"

    with pytest.raises(ValueError, match="case identity/status/cost changed"):
        validate_report(root, report)
