"""Verify DEV2-CONTEXT-001 result integrity without granting promotion."""

from __future__ import annotations

import argparse
import math
import re
from pathlib import Path
from typing import Any

from scripts.verify_registered_missingness import metrics, partition
from scripts.verify_registered_research_v2 import require, safe_aggregate
from training.v2.context_analysis import CONTROLS, ENDPOINTS, matrix_choices
from training.v2.provenance import read_object, sha256_file
from training.v2.registered_context import (
    REGISTRATION_SHA256,
    VIEWS,
    load_registration,
)
from training.v2.run_registered_context import verify_artifacts

REPORT_PATH = "docs/research-v2/registered-results/DEV2-CONTEXT-001.json"
REPORT_SHA256 = "e5bc778271823a5b2bc30d60bb7aa125212fad58863a73e6c81dbeb921540909"
EXECUTION_COMMIT = "8071496690ce9d3150cd1209d7035b29584502bd"
SHA = re.compile(r"[0-9a-f]{64}")


def close(left: float, right: float) -> bool:
    return math.isclose(left, right, rel_tol=1e-10, abs_tol=1e-12)


def matrix_binding(value: dict[str, Any], rows: int, width: int) -> None:
    require(
        value["rows"] == rows
        and value["dimension"] == width
        and type(value["distinct_inputs"]) is int
        and 0 < value["distinct_inputs"] <= rows
        and SHA.fullmatch(value["float64_le_sha256"]) is not None,
        "invalid context input provenance",
    )


def _rate(value: dict[str, Any]) -> float:
    require(
        type(value["rows"]) is int
        and value["rows"] > 0
        and type(value["count"]) is int
        and 0 <= value["count"] <= value["rows"]
        and close(value["rate"], value["count"] / value["rows"]),
        "invalid context rate",
    )
    return float(value["rate"])


def validate_site(
    site: dict[str, Any],
    case: dict[str, Any],
    orientation: dict[str, str],
    config: dict[str, Any],
) -> None:
    require(
        site["status"] == "evaluated" and site["orientation"] == orientation,
        "context site orientation/status changed",
    )
    parts = site["partition_provenance"]
    require(
        set(parts) == {"fit", "site_calibration", "benign_test", "target"},
        "context site partition roles changed",
    )
    for value in parts.values():
        partition(value)
    require(
        parts["fit"] == case["partition_provenance"]["fit"]
        and parts["target"] == case["partition_provenance"]["target"]
        and parts["fit"]["scenarios"]
        == sorted([*case["fit_sources"], config["splits"]["background_benign"]])
        and parts["target"]["scenarios"] == [case["target_capture"]]
        and parts["site_calibration"]["scenarios"] == [orientation["calibration"]]
        and parts["benign_test"]["scenarios"] == [orientation["benign_test"]]
        and parts["site_calibration"]["binary_labels"]
        == {"benign": parts["site_calibration"]["rows"]}
        and parts["benign_test"]["binary_labels"]
        == {"benign": parts["benign_test"]["rows"]},
        "context site partitions violate registered roles",
    )
    inputs = site["input_provenance"]
    require(
        set(inputs) == {"site_calibration", "benign_test", "target"},
        "context site input roles changed",
    )
    for role, value in inputs.items():
        matrix_binding(value, parts[role]["rows"], config["representation"]["dimension"])

    cuts = site["thresholds"]
    require(
        set(cuts) == {"known_direct", "known_review", "ood_direct", "ood_review"}
        and all(math.isfinite(value) for value in cuts.values())
        and cuts["known_review"] <= cuts["known_direct"]
        and cuts["ood_review"] <= cuts["ood_direct"],
        "context site thresholds are invalid",
    )
    metrics(site["calibration"], parts["site_calibration"]["rows"])
    metrics(site["target"], parts["target"]["rows"])
    metrics(site["independent_benign"], parts["benign_test"]["rows"])
    combined_rows = parts["target"]["rows"] + parts["benign_test"]["rows"]
    metrics(site["combined"], combined_rows)
    calibration = site["calibration"]["benign"]
    require(
        _rate(calibration["direct_union_fpr"])
        <= config["calibration"]["direct_union_budget"]
        and _rate(calibration["review_inclusive_rate"])
        <= config["calibration"]["review_inclusive_union_budget"],
        "context empirical calibration exceeds registered budget",
    )
    expected_confusion = [
        [
            site["combined"][truth]["four_verdict_counts"][verdict]
            for verdict in site["confusion_verdict_order"]
        ]
        for truth in ("benign", "attack")
    ]
    require(
        site["confusion_truth_order"] == ["benign", "attack"]
        and site["confusion_verdict_order"]
        == ["known_attack", "suspicious_unknown", "needs_review", "benign"]
        and site["confusion_matrix"] == expected_confusion,
        "context confusion matrix changed",
    )
    family_rows = 0
    for family, value in site["target_families"].items():
        require(family != "benign", "benign cannot be a target attack family")
        family_count = parts["target"]["families"][family]
        metrics(value["metrics"], family_count)
        family_rows += family_count
        require(
            value["present_in_supervised_fit"]
            == (family in parts["fit"]["families"]),
            "context family fit-presence flag changed",
        )
    require(
        family_rows == parts["target"]["binary_labels"]["malicious"],
        "context target-family rows do not cover attacks",
    )
    inference = site["inference"]
    require(
        [entry["batch_size"] for entry in inference]
        == config["measurement"]["batch_sizes"],
        "context inference batch sizes changed",
    )
    for entry in inference:
        require(
            entry["warmup_calls"]
            == config["measurement"]["warmup_calls_per_batch_size"]
            and entry["measured_calls"]
            == config["measurement"]["measured_calls_per_batch_size"]
            and entry["scope"] == config["measurement"]["inference_scope"]
            and entry["throughput_flows_per_second"] > 0
            and entry["not_durable_pipeline_throughput"] is True
            and SHA.fullmatch(entry["batch_record_content_sha256"]) is not None,
            "invalid context inference measurement",
        )


def validate_paired(report: dict[str, Any], config: dict[str, Any]) -> None:
    paired = report["paired_analysis"]
    require(
        paired["comparisons"] == config["paired_analysis"]["comparisons"]
        and paired["terminal_reference_excluded_from_benefit_rule"] is True
        and paired["interpretation"] == config["paired_analysis"]["interpretation"],
        "context paired-analysis contract changed",
    )
    expected = [
        (target, index, orientation, control)
        for target in config["splits"]["attack_environments"]
        for index, orientation in enumerate(config["splits"]["site_orientations"], start=1)
        for control in CONTROLS
    ]
    require(len(paired["strata"]) == len(expected) == 12, "context paired strata incomplete")
    decisions: dict[str, list[dict[str, Any]]] = {control: [] for control in CONTROLS}
    for entry, (target, index, orientation, control) in zip(
        paired["strata"], expected, strict=True
    ):
        require(
            entry["status"] == "evaluated"
            and entry["stratum_id"] == f"{target}|orientation-{index}"
            and entry["target_capture"] == target
            and entry["orientation"] == orientation
            and entry["control"] == control
            and len(entry["case_ids"]) == 6
            and set(entry["endpoints"]) == set(ENDPOINTS),
            "context paired stratum changed",
        )
        for endpoint, value in entry["endpoints"].items():
            interval = value["paired_bootstrap_95"]
            require(
                type(value["rows"]) is int
                and value["rows"] > 0
                and value["fit_choices_averaged_per_row"] == 3
                and value["bootstrap_replicates"]
                == config["paired_analysis"]["bootstrap_replicates"]
                and all(
                    math.isfinite(number)
                    for number in (
                        value["causal_rate"],
                        value["control_rate"],
                        value["delta"],
                        *interval,
                    )
                )
                and 0 <= value["causal_rate"] <= 1
                and 0 <= value["control_rate"] <= 1
                and close(
                    value["delta"], value["causal_rate"] - value["control_rate"]
                )
                and len(interval) == 2
                and interval[0] <= interval[1],
                f"invalid paired endpoint {endpoint}",
            )
        qualifies = (
            entry["endpoints"]["target_attack_direct"]["paired_bootstrap_95"][0] > 0
            and entry["endpoints"]["target_attack_or_review"][
                "paired_bootstrap_95"
            ][0]
            > 0
            and entry["endpoints"]["independent_benign_direct"][
                "paired_bootstrap_95"
            ][1]
            <= config["paired_analysis"]["benefit_max_safety_upper_delta"]
        )
        require(
            entry["benefit_qualifying"] is qualifies,
            "context paired benefit flag disagrees with intervals",
        )
        decisions[control].append(entry)

    recomputed = {}
    for control, entries in decisions.items():
        qualified = [entry for entry in entries if entry["benefit_qualifying"]]
        targets = {entry["target_capture"] for entry in qualified}
        orientations = {
            (entry["orientation"]["calibration"], entry["orientation"]["benign_test"])
            for entry in qualified
        }
        expected_targets = set(config["splits"]["attack_environments"])
        all_targets = targets == expected_targets
        all_orientations = len(orientations) == len(config["splits"]["site_orientations"])
        benefit = (
            len(qualified)
            >= config["paired_analysis"]["benefit_minimum_positive_strata_per_control"]
            and all_targets
            and all_orientations
        )
        recomputed[control] = {
            "benefit_detected": benefit,
            "qualifying_strata": len(qualified),
            "required_strata": config["paired_analysis"][
                "benefit_minimum_positive_strata_per_control"
            ],
            "all_targets_represented": all_targets,
            "all_orientations_represented": all_orientations,
        }
    overall = all(value["benefit_detected"] for value in recomputed.values())
    require(
        paired["control_decisions"] == recomputed
        and paired["benefit_detected"] is overall
        and paired["scientific_conclusion"]
        == (
            "detectable_causal_benefit_under_registered_rule"
            if overall
            else "null_no_detectable_causal_benefit_under_registered_rule"
        ),
        "context final paired decision changed",
    )


def validate_report(root: Path, report: dict[str, Any]) -> None:
    safe_aggregate(report)
    config = load_registration(root)
    require(
        report["schema_version"] == "1.0.0"
        and report["experiment_id"] == "DEV2-CONTEXT-001"
        and report["execution_status"] == "completed"
        and report["scientific_status"] == "development_only_no_candidate_selected"
        and report["code_commit"] == EXECUTION_COMMIT
        and report["registration"] == config
        and report["registration_sha256_utf8_lf"] == REGISTRATION_SHA256,
        "context result status or registration changed",
    )
    require(
        report["preparation_manifest"]
        == read_object(root / config["prepared_manifest"]["path"])
        and report["context_manifest"]
        == read_object(root / config["context_manifest"]["path"]),
        "context result input manifests changed",
    )
    cohort = report["cohort"]
    for name in (
        "input",
        "cross_capture_excluded",
        "within_capture_ambiguous_excluded",
        "within_capture_duplicate_rows",
        "retained",
    ):
        partition(cohort[name], allow_empty=True)
    expected_cohort = config["cohort"]
    require(
        cohort["input_core_groups"] == expected_cohort["core_groups"]
        and cohort["cross_capture_groups"] == expected_cohort["cross_capture_groups"]
        and cohort["groups_with_optional_packet_variants"]
        == expected_cohort["groups_with_optional_packet_variants"]
        and cohort["retained"]["rows"] == expected_cohort["retained_rows"]
        and cohort["retained"]["event_ids_sha256"]
        == expected_cohort["retained_event_ids_sha256"]
        and cohort["retained"]["records_sha256"]
        == expected_cohort["retained_records_sha256"],
        "context result cohort changed",
    )
    choices = matrix_choices(config)
    expected_cases = [
        (number, target, sources, view)
        for number, (target, sources) in enumerate(choices, start=1)
        for view in VIEWS
    ]
    cases = report["cases"]
    require(len(cases) == len(expected_cases) == 36, "context cases incomplete")
    for case, (number, target, sources, view) in zip(cases, expected_cases, strict=True):
        case_id = f"choice{number:02d}-{view}"
        require(
            case["case_id"] == case_id
            and case["target_capture"] == target
            and case["fit_sources"] == sources
            and case["view"] == view
            and case["status"] == "evaluated"
            and case["fit_attempted"] is True
            and case["feature_build_seconds"] > 0
            and case["fit_seconds"] > 0
            and case["model_wall_seconds"] >= case["fit_seconds"],
            "context case identity/status/cost changed",
        )
        parts = case["partition_provenance"]
        require(
            set(parts) == {"fit", "site_calibration", "benign_test", "target"},
            "context case partition roles changed",
        )
        for value in parts.values():
            partition(value)
        require(
            set(parts["fit"]["binary_labels"]) == {"benign", "malicious"}
            and max(parts["fit"]["binary_labels"].values())
            <= config["splits"]["fit_per_binary_class_cap"],
            "context fit partition violates registered cap/classes",
        )
        for collection in (case["raw_inputs"], case["transformed_inputs"]):
            require(set(collection) == set(parts), "context case input roles changed")
            for role, value in collection.items():
                matrix_binding(
                    value, parts[role]["rows"], config["representation"]["dimension"]
                )
        artifact = case["artifact"]
        require(
            artifact["file"] == f"{case_id}.npz"
            and artifact["view"] == view
            and artifact["format"] == "numpy_numeric_arrays_no_pickle"
            and SHA.fullmatch(artifact["sha256"]) is not None
            and artifact["bytes"] > 0
            and artifact["arrays"]["view_sha256"]
            == {"shape": [32], "dtype": "uint8"},
            "context artifact declaration changed",
        )
        memory = case["memory"]
        require(
            memory["scope"] == config["measurement"]["memory_scope"]
            and memory["sampling_interval_ms"]
            == config["measurement"]["memory_sampling_interval_ms"]
            and memory["sampled_peak_rss_bytes"]
            >= max(memory["rss_before_bytes"], memory["rss_after_bytes"]),
            "context case memory measurement changed",
        )
        require(len(case["site_evaluations"]) == 2, "context site evaluations incomplete")
        for site, orientation in zip(
            case["site_evaluations"], config["splits"]["site_orientations"], strict=True
        ):
            validate_site(site, case, orientation, config)

    coverage = report["coverage"]
    require(
        coverage
        == {
            "planned_model_entries": 36,
            "linear_fit_attempts": 36,
            "evaluated_models": 36,
            "evaluated_site_entries": 72,
            "planned_site_entries": 72,
        },
        "context result coverage changed",
    )
    pools = report["environment"]["numerical_pools"]
    require(
        bool(pools) and all(pool["num_threads"] == 1 for pool in pools),
        "context result numerical thread limit changed",
    )
    require(
        report["elapsed_seconds"] > 0 and report["cohort_construction_seconds"] > 0,
        "context result execution costs are missing",
    )
    validate_paired(report, config)


def validate_local_evidence(root: Path, directory: Path, report: dict[str, Any]) -> None:
    require(
        read_object(directory / "report.json") == report,
        "local context report differs from selected report",
    )
    attempt = read_object(directory / "attempt.json")
    require(
        attempt["experiment_id"] == "DEV2-CONTEXT-001"
        and attempt["code_commit"] == EXECUTION_COMMIT
        and attempt["registration_sha256_utf8_lf"] == REGISTRATION_SHA256
        and attempt["status"] == "attempt_started_not_completion_evidence",
        "local context attempt ledger changed",
    )
    for case in report["cases"]:
        require(
            read_object(directory / f"{case['case_id']}.json") == case,
            "local context case file differs from aggregate report",
        )
    require(
        verify_artifacts(directory, report["cases"], load_registration(root)) == 36,
        "local context artifacts are incomplete",
    )
    expected = {
        "attempt.json",
        "report.json",
        *[f"{case['case_id']}.json" for case in report["cases"]],
        *[case["artifact"]["file"] for case in report["cases"]],
    }
    require(
        {path.name for path in directory.iterdir()} == expected,
        "local context evidence directory has unbound files",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--local-evidence-dir", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    path = args.report or root / REPORT_PATH
    require(sha256_file(path) == REPORT_SHA256, "context result bytes changed")
    report = read_object(path)
    validate_report(root, report)
    if args.local_evidence_dir is not None:
        validate_local_evidence(root, args.local_evidence_dir, report)
    print(
        "verified DEV2-CONTEXT-001 result: 36 models, 72 sites, "
        f"benefit_detected={report['paired_analysis']['benefit_detected']}; "
        "development only"
    )


if __name__ == "__main__":
    main()

