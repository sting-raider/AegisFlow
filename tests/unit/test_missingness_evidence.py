from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from scripts import verify_registered_missingness as evidence
from training.v2.provenance import read_object

ROOT = Path(__file__).resolve().parents[2]


def test_missingness_report_is_complete_hash_bound_and_reproducibly_summarized() -> None:
    report = evidence.verify(ROOT)
    assert report["coverage"] == {
        "planned_model_entries": 108,
        "linear_fit_attempts": 84,
        "evaluated_models": 84,
        "planned_site_entries": 216,
        "evaluated_site_entries": 168,
    }
    summary = evidence.render_summary(report)
    assert (ROOT / evidence.REPORT_PATH).with_suffix(".md").read_text(encoding="utf-8") == summary
    assert "52/72 target/view/transform/site" in summary
    assert "44/72 source-choice/transform/site" in summary
    assert summary.count("| ineligible |") == 24


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_missingness_public_hash_is_checkout_independent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, newline: str
) -> None:
    path = tmp_path / "report.json"
    path.write_text(
        (ROOT / evidence.REPORT_PATH).read_text(encoding="utf-8"), encoding="utf-8", newline=newline
    )
    monkeypatch.setattr(evidence, "REPORT_PATH", str(path))
    assert evidence.verify(ROOT)["execution_status"] == "completed"
    with path.open("a", encoding="utf-8") as stream:
        stream.write(" ")
    with pytest.raises(ValueError, match="report hash"):
        evidence.verify(ROOT)


@pytest.mark.parametrize(
    "mutation",
    [
        "registration",
        "execution",
        "cohort",
        "missing_case",
        "duplicate_case",
        "view",
        "coverage",
        "fit_attempt",
        "cost",
        "observation",
        "observed_prefix",
        "transformed",
        "fit_site_leak",
        "site_swap",
        "counts",
        "f1",
        "binary_interpretation",
        "unknown",
        "family_seen",
        "family_counts",
        "paired_delta",
        "missing_comparison",
        "artifact",
        "failed_artifact",
        "failed_score",
        "failed_cost",
        "batch_cost",
        "pipeline_claim",
        "private_rows",
        "nonfinite",
    ],
)
def test_missingness_semantic_mutations_fail_before_hash_check(mutation: str) -> None:
    report = deepcopy(read_object(ROOT / evidence.REPORT_PATH))
    case = report["cases"][0]
    site = case["site_evaluations"][0]
    failed = next(c for c in report["cases"] if c["status"] == "ineligible")
    if mutation == "registration":
        report["registration"]["execution"]["seed"] += 1
    elif mutation == "execution":
        report["code_commit"] = "0" * 40
    elif mutation == "cohort":
        report["cohort"]["retained"]["records_sha256"] = "0" * 64
    elif mutation == "missing_case":
        report["cases"].pop()
    elif mutation == "duplicate_case":
        report["cases"][-1] = deepcopy(case)
    elif mutation == "view":
        case["feature_order"].reverse()
    elif mutation == "coverage":
        report["coverage"]["evaluated_models"] = 108
    elif mutation == "fit_attempt":
        failed["fit_attempted"] = True
    elif mutation == "cost":
        case["fit_seconds"] = 0
    elif mutation == "observation":
        case["observation_support"]["target"]["observed_counts_by_feature"][0] -= 1
    elif mutation == "observed_prefix":
        case["observation_support"]["target"]["observed_counts_by_feature"][10] -= 1
    elif mutation == "transformed":
        case["transformed_inputs"]["target"]["dimension"] += 1
    elif mutation == "fit_site_leak":
        case["partition_provenance"]["fit"]["scenarios"].append("CTU-Honeypot-Capture-4-1")
    elif mutation == "site_swap":
        site["partition_provenance"]["benign_test"] = deepcopy(
            site["partition_provenance"]["site_calibration"]
        )
    elif mutation == "counts":
        site["combined"]["four_verdict_counts"]["benign"] += 1
    elif mutation == "f1":
        site["combined"]["binary_metrics"]["macro_f1"] += 0.01
    elif mutation == "binary_interpretation":
        site["combined"]["binary_metrics"]["positive_prediction"] = "uncertainty"
    elif mutation == "unknown":
        site["target"]["attack"]["direct_suspicious_unknown"]["rate"] = 0.99
    elif mutation == "family_seen":
        family = next(iter(site["target_families"].values()))
        family["present_in_supervised_fit"] = not family["present_in_supervised_fit"]
    elif mutation == "family_counts":
        next(iter(site["target_families"].values()))["metrics"]["rows"] += 1
    elif mutation == "paired_delta":
        paired = next(p for p in report["source_addition_comparisons"] if p["status"] == "paired")
        paired["combined_minus_single"][0]["target_attack_unknown"] += 0.01
    elif mutation == "missing_comparison":
        report["source_addition_comparisons"].pop()
    elif mutation == "artifact":
        case["artifact"]["file"] = "../weights.npz"
    elif mutation == "failed_artifact":
        failed["artifact"] = deepcopy(case["artifact"])
    elif mutation == "failed_score":
        failed["site_evaluations"][0]["target"] = deepcopy(site["target"])
    elif mutation == "failed_cost":
        failed.pop("fit_seconds")
    elif mutation == "batch_cost":
        site["inference"][0]["measured_calls"] = 1
    elif mutation == "pipeline_claim":
        site["inference"][0]["not_durable_pipeline_throughput"] = False
    elif mutation == "private_rows":
        report["event_ids"] = ["not-public"]
    elif mutation == "nonfinite":
        report["elapsed_seconds"] = float("nan")
    with pytest.raises(ValueError):
        evidence.validate_report(ROOT, report)


def test_missingness_artifacts_required_only_for_local_artifact_check(tmp_path: Path) -> None:
    with pytest.raises((ValueError, FileNotFoundError)):
        evidence.verify(ROOT, artifact_directory=tmp_path)


def test_representation_summary_refuses_unpaired_raw_cohorts() -> None:
    report = read_object(ROOT / evidence.REPORT_PATH)
    report["cases"][4]["partition_provenance"]["target"]["records_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="representation comparisons are not paired"):
        evidence.comparison_tables(report)


def test_no_paired_deltas_are_not_reported_as_zero() -> None:
    assert "unevaluable" in evidence.delta_row("test", [])
    assert evidence.delta_row("test", [0.0, 0.1, -0.2]) == ("| test | 1 | 1 | 1 | -20.00 / 10.00 |")
