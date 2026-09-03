"""Check registered missingness evidence without granting scientific acceptance."""

from __future__ import annotations

import argparse
import math
import re
from pathlib import Path
from typing import Any

from scripts.verify_registered_research_v2 import require, safe_aggregate, validate_metrics
from training.v2.missingness import INPUT_NAMES, MissingnessTransform
from training.v2.provenance import read_object
from training.v2.registered_family import VERDICTS, text_digest
from training.v2.registered_missingness import matrix_choices, paired_comparisons, verify_artifacts
from training.v2.transfer_support import REGISTRATION_SHA256, load_registration

REPORT_PATH = "docs/research-v2/registered-results/DEV2-MISSINGNESS-001.json"
REPORT_SHA256 = "c0d7685393ebd76abbdbb78a75ce3ed40a62a925ea5a9e6a8aa19fcca7966961"
EXECUTION_COMMIT = "b83f184d583d5d1f719c1be4702968516c3fd5f9"
SHA = re.compile(r"[0-9a-f]{64}")


def close(left: float, right: float) -> bool:
    return math.isclose(left, right, rel_tol=1e-10, abs_tol=1e-12)


def partition(value: dict[str, Any], *, allow_empty: bool = False) -> None:
    n = value["rows"]
    require(type(n) is int and n >= (0 if allow_empty else 1), "invalid partition rows")
    require(
        all(
            SHA.fullmatch(value[key]) is not None for key in ("event_ids_sha256", "records_sha256")
        ),
        "invalid partition fingerprints",
    )
    require(
        sum(value["families"].values()) == n == sum(value["binary_labels"].values()),
        "partition label counts disagree",
    )
    require(
        all(
            type(count) is int and count >= 0
            for field in ("families", "binary_labels")
            for count in value[field].values()
        ),
        "invalid partition label counts",
    )
    require(set(value["binary_labels"]) <= {"benign", "malicious"}, "invalid partition labels")
    require(
        value["families"].get("benign", 0) == value["binary_labels"].get("benign", 0),
        "partition family/binary labels disagree",
    )


def metrics(value: dict[str, Any], rows: int) -> None:
    validate_metrics(value)
    require(value["rows"] == rows, "metric rows differ from partition")
    for label in ("benign", "attack"):
        if label not in value:
            continue
        group = value[label]
        require(
            group["direct_suspicious_unknown"]["count"]
            <= group["ood_channel"]["count"]
            <= group["direct_detection"]["count"],
            "OOD channel/verdict counts disagree",
        )
        for name in (
            "score_quantiles",
            "distance_quantiles",
            "ood_calibration_percentile_quantiles",
        ):
            if name not in group:
                continue
            values = [group[name][key] for key in ("min", "p25", "p50", "p75", "p95", "p99", "max")]
            require(values == sorted(values) and values[0] >= 0, "invalid score quantiles")
            if name != "distance_quantiles":
                require(values[-1] <= 1, "invalid probability/percentile quantiles")
    if "benign" in value and "attack" in value:
        benign, attack = value["benign"], value["attack"]
        tp, fp = attack["direct_detection"]["count"], benign["direct_detection"]["count"]
        fn, tn = attack["rows"] - tp, benign["rows"] - fp
        positive = 2 * tp / max(2 * tp + fp + fn, 1)
        negative = 2 * tn / max(2 * tn + fp + fn, 1)
        binary = value["binary_metrics"]
        require(
            binary["positive_prediction"] == "known_attack_or_suspicious_unknown",
            "binary metric interpretation changed",
        )
        require(
            close(binary["macro_f1"], (positive + negative) / 2)
            and close(
                binary["weighted_f1"],
                (positive * attack["rows"] + negative * benign["rows"]) / rows,
            ),
            "binary F1 disagrees with verdict confusion",
        )
        require(
            all(
                0 <= binary[key] <= 1
                for key in (
                    "known_score_pr_auc",
                    "known_score_brier",
                    "known_score_ece_10_equal_width_bins",
                )
            ),
            "invalid supervised probability metrics",
        )


def validate_report(root: Path, report: dict[str, Any]) -> None:
    try:
        safe_aggregate(report)
        config = load_registration(root)
        require(
            report["registration"] == config
            and report["registration_sha256_utf8_lf"] == REGISTRATION_SHA256,
            "missingness registration mismatch",
        )
        require(report["code_commit"] == EXECUTION_COMMIT, "execution commit mismatch")
        require(
            report["execution_status"] == "completed"
            and report["scientific_status"] == "development_only_no_candidate_selected",
            "invalid missingness evidence status",
        )
        require(
            report["preparation_manifest"]
            == read_object(root / config["prepared_manifest"]["path"]),
            "preparation binding mismatch",
        )
        require(
            report["elapsed_seconds"] > 0 and report["cohort_construction_seconds"] > 0,
            "missing execution measurements",
        )
        pools = report["environment"]["numerical_pools"]
        require(
            bool(pools) and all(item["num_threads"] == 1 for item in pools),
            "numerical thread budget not verified",
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
        require(
            cohort["input"]["rows"]
            == config["prepared_manifest"]["expected_rows"]
            == sum(
                cohort[name]["rows"]
                for name in (
                    "cross_capture_excluded",
                    "within_capture_ambiguous_excluded",
                    "within_capture_duplicate_rows",
                    "retained",
                )
            ),
            "cohort rows not conserved",
        )
        expected = config["cohort"]
        for name, actual in {
            "core_groups": cohort["input_core_groups"],
            "cross_capture_groups": cohort["cross_capture_groups"],
            "groups_with_optional_packet_variants": cohort["groups_with_optional_packet_variants"],
            "cross_capture_excluded_rows": cohort["cross_capture_excluded"]["rows"],
            "within_capture_ambiguous_excluded_rows": cohort["within_capture_ambiguous_excluded"][
                "rows"
            ],
            "within_capture_duplicate_rows": cohort["within_capture_duplicate_rows"]["rows"],
            "retained_rows": cohort["retained"]["rows"],
            "retained_event_ids_sha256": cohort["retained"]["event_ids_sha256"],
            "retained_records_sha256": cohort["retained"]["records_sha256"],
        }.items():
            require(actual == expected[name], "common-support counts or digest changed")
        cases = report["cases"]
        expected_cases = [
            (number, target, sources, view, kind)
            for number, (target, sources) in enumerate(matrix_choices(config), start=1)
            for view in config["representation"]["views"]
            for kind in config["representation"]["transforms"]
        ]
        require(len(cases) == len(expected_cases) == 108, "missingness matrix incomplete")
        artifacts: set[str] = set()
        fits = sites_evaluated = 0
        for case, (number, target, sources, view, kind) in zip(cases, expected_cases, strict=True):
            name = f"choice{number:02d}-{view}-{kind}"
            require(
                (
                    case["case_id"],
                    case["target_capture"],
                    case["fit_sources"],
                    case["view"],
                    case["transform"],
                )
                == (name, target, sources, view, kind),
                "missingness case reordered or changed",
            )
            require(type(case["fit_attempted"]) is bool, "fit attempt count not explicit")
            fits += int(case["fit_attempted"])
            transform = MissingnessTransform(view, kind, seed=config["execution"]["seed"])
            require(case["feature_order"] == list(transform.feature_names), "feature order changed")
            parts = case["partition_provenance"]
            require(
                set(parts) == {"fit", "site_calibration", "benign_test", "target"},
                "case partition roles incomplete",
            )
            for role, part in parts.items():
                partition(part)
                observed = case["observation_support"][role]
                counts = observed["observed_counts_by_feature"]
                require(
                    observed["rows"] == part["rows"]
                    and len(counts) == len(INPUT_NAMES)
                    and all(type(c) is int and 0 <= c <= part["rows"] for c in counts)
                    and counts[:9] == [part["rows"]] * 9,
                    "observation support changed",
                )
                require(
                    counts[9::3] == counts[10::3] == counts[11::3]
                    and counts[9::3] == sorted(counts[9::3], reverse=True)
                    and observed["fully_observed_rows"] == counts[-1]
                    and observed["rows_without_observed_packets"] == part["rows"] - counts[9]
                    and observed["unobserved_meaning"]
                    == "no_complete_packet_metadata_for_slot_not_inferred_packet_loss",
                    "packet availability is not a common observed prefix",
                )
                binding = case["transformed_inputs"][role]
                require(
                    binding["rows"] == part["rows"]
                    and binding["dimension"] == len(transform.feature_names)
                    and 0 < binding["distinct_inputs"] <= part["rows"]
                    and SHA.fullmatch(binding["float64_le_sha256"]) is not None,
                    "transformed-input binding invalid",
                )
            require(
                set(parts["fit"]["scenarios"]) <= {*sources, config["splits"]["background_benign"]}
                and set(parts["fit"]["binary_labels"]) == {"benign", "malicious"}
                and max(parts["fit"]["binary_labels"].values())
                <= config["splits"]["fit_per_binary_class_cap"]
                and parts["target"]["scenarios"] == [target],
                "fit/target capture leakage",
            )
            original = config["splits"]["site_orientations"][0]
            for role, key in (("site_calibration", "calibration"), ("benign_test", "benign_test")):
                require(
                    parts[role]["scenarios"] == [original[key]]
                    and parts[role]["binary_labels"] == {"benign": parts[role]["rows"]},
                    "site role is not independent benign-only",
                )
            memory = case["memory"]
            require(
                case["fit_seconds"] > 0
                and case["feature_build_seconds"] > 0
                and case["model_wall_seconds"] >= case["fit_seconds"]
                and memory["sampled_peak_rss_bytes"]
                >= max(memory["rss_before_bytes"], memory["rss_after_bytes"])
                > 0
                and memory["sampling_interval_ms"] == 10,
                "missing attempted-case costs",
            )
            site_entries = case["site_evaluations"]
            require(len(site_entries) == 2, "site coverage incomplete")
            if case["status"] == "ineligible":
                require(
                    bool(case["reason"])
                    and "artifact" not in case
                    and case["failure_phase"] in {"preprocessing", "linear_fit", "ood_fit"},
                    "invalid ineligible case evidence",
                )
                require(
                    case["fit_attempted"] == (case["failure_phase"] != "preprocessing"),
                    "failed fit attempt accounting mismatch",
                )
            else:
                require(
                    case["status"] == "evaluated" and case["fit_attempted"], "invalid case status"
                )
                artifact = case["artifact"]
                require(
                    artifact["file"] == f"{name}.npz"
                    and artifact["file"] not in artifacts
                    and artifact["bytes"] > 0
                    and artifact["format"] == "numpy_numeric_arrays_no_pickle"
                    and SHA.fullmatch(artifact["sha256"]) is not None,
                    "invalid model artifact binding",
                )
                artifacts.add(artifact["file"])
            for index, site in enumerate(site_entries):
                require(
                    site["orientation"] == config["splits"]["site_orientations"][index],
                    "site orientation changed",
                )
                if case["status"] == "ineligible":
                    require(
                        site["status"] == "ineligible_model"
                        and "target" not in site
                        and site["reason"] == case["reason"],
                        "failed model fabricated site score",
                    )
                    continue
                require(site["status"] == "evaluated", "evaluated model missing a site")
                sites_evaluated += 1
                expected_parts = dict(parts)
                if index == 1:
                    expected_parts["site_calibration"], expected_parts["benign_test"] = (
                        parts["benign_test"],
                        parts["site_calibration"],
                    )
                require(site["partition_provenance"] == expected_parts, "site rows not paired")
                cuts = site["thresholds"]
                require(
                    set(cuts) == {"known_direct", "known_review", "ood_direct", "ood_review"}
                    and cuts["known_review"] <= cuts["known_direct"]
                    and cuts["ood_review"] <= cuts["ood_direct"],
                    "threshold order invalid",
                )
                for key, role in (
                    ("target", "target"),
                    ("calibration", "site_calibration"),
                    ("independent_benign", "benign_test"),
                ):
                    metrics(site[key], expected_parts[role]["rows"])
                    require(
                        site[key].get("benign", {}).get("rows", 0)
                        == expected_parts[role]["binary_labels"].get("benign", 0),
                        "evaluation ground-truth counts changed",
                    )
                cal = site["calibration"]["benign"]
                require(
                    cal["direct_union_fpr"]["rate"] <= config["calibration"]["direct_union_budget"]
                    and cal["review_inclusive_rate"]["rate"]
                    <= config["calibration"]["review_inclusive_union_budget"],
                    "calibration budget violated",
                )
                combined = site["combined"]
                metrics(
                    combined,
                    expected_parts["target"]["rows"] + expected_parts["benign_test"]["rows"],
                )
                for label in ("benign", "attack"):
                    expected_counts = {
                        verdict: sum(
                            site[role].get(label, {}).get("four_verdict_counts", {}).get(verdict, 0)
                            for role in ("target", "independent_benign")
                        )
                        for verdict in VERDICTS
                    }
                    require(
                        combined[label]["four_verdict_counts"] == expected_counts,
                        "combined confusion does not conserve evaluation counts",
                    )
                require(
                    site["confusion_truth_order"] == ["benign", "attack"]
                    and site["confusion_verdict_order"] == list(VERDICTS)
                    and site["confusion_matrix"]
                    == [
                        [combined[label]["four_verdict_counts"][v] for v in VERDICTS]
                        for label in ("benign", "attack")
                    ],
                    "confusion table mismatch",
                )
                require(
                    set(site["target_families"]) == set(parts["target"]["families"]) - {"benign"},
                    "target family coverage changed",
                )
                for family, entry in site["target_families"].items():
                    require(
                        entry["present_in_supervised_fit"] is (family in parts["fit"]["families"]),
                        "cross-capture family misrepresented as held out",
                    )
                    metrics(entry["metrics"], parts["target"]["families"][family])
                require(
                    site["target"]["attack"]["four_verdict_counts"]
                    == {
                        verdict: sum(
                            entry["metrics"]["attack"]["four_verdict_counts"][verdict]
                            for entry in site["target_families"].values()
                        )
                        for verdict in VERDICTS
                    },
                    "target family confusion does not conserve attack counts",
                )
                batches = site["inference"]
                require(
                    [b["batch_size"] for b in batches] == config["measurement"]["batch_sizes"],
                    "inference batches incomplete",
                )
                for batch in batches:
                    require(
                        batch["warmup_calls"] == 10
                        and batch["measured_calls"] == 100
                        and batch["scope"] == config["measurement"]["inference_scope"]
                        and batch["throughput_flows_per_second"] > 0
                        and batch["not_durable_pipeline_throughput"] is True
                        and SHA.fullmatch(batch["batch_record_content_sha256"]) is not None
                        and 0
                        < batch["batch_latency_ms"]["p50"]
                        <= batch["batch_latency_ms"]["p95"]
                        <= batch["batch_latency_ms"]["p99"]
                        and sum(batch["batch_family_counts"].values()) == batch["batch_size"],
                        "inference cost evidence invalid",
                    )
        require(
            report["coverage"]
            == {
                "planned_model_entries": 108,
                "linear_fit_attempts": fits,
                "evaluated_models": len(artifacts),
                "evaluated_site_entries": sites_evaluated,
                "planned_site_entries": 216,
            },
            "coverage accounting mismatch",
        )
        require(
            report["source_addition_comparisons"] == paired_comparisons(cases, config),
            "source-addition deltas or missing comparisons changed",
        )
    except (KeyError, TypeError, IndexError, ZeroDivisionError) as error:
        raise ValueError("incompatible missingness evidence schema") from error


def verify(root: Path, *, artifact_directory: Path | None = None) -> dict[str, Any]:
    require(text_digest(root / REPORT_PATH) == REPORT_SHA256, "missingness report hash mismatch")
    report = read_object(root / REPORT_PATH)
    validate_report(root, report)
    if artifact_directory is not None:
        require(
            verify_artifacts(artifact_directory, report["cases"], report["registration"])
            == report["coverage"]["evaluated_models"],
            "local model count mismatch",
        )
    return report


def render_summary(report: dict[str, Any]) -> str:
    coverage = report["coverage"]
    lines = [
        "# Packet availability and cross-capture transfer",
        "",
        f"Executed commit: `{report['code_commit']}`. Development-only common-support cohort.",
        "",
        f"Coverage: {coverage['evaluated_models']}/108 evaluated models; "
        f"{coverage['evaluated_site_entries']}/216 evaluated site entries. "
        "Failed entries are not assigned zero scores.",
        "",
        "Each cell lists the two calibration-site orientations as percentages. "
        "Unknown is direct suspicious-unknown recall; review includes any detection/review. "
        "FPR uses the independent benign site, not its calibration sample.",
        "",
        "| Target | Fit attack source(s) | View | Transform | Unknown | "
        "Detection/review | Benign FPR |",
        "|---|---|---|---|---:|---:|---:|",
    ]

    def short(scenario: str) -> str:
        return scenario.removeprefix("CTU-IoT-Malware-Capture-")

    for case in report["cases"]:
        identity = [
            short(case["target_capture"]),
            "+".join(map(short, case["fit_sources"])),
            case["view"],
            case["transform"],
        ]
        if case["status"] != "evaluated":
            cells = ["ineligible", "—", "—"]
        else:
            sites = case["site_evaluations"]
            cells = [
                " / ".join(
                    f"{site['target']['attack'][metric]['rate'] * 100:.2f}" for site in sites
                )
                for metric in ("direct_suspicious_unknown", "detection_or_review")
            ]
            cells.append(
                " / ".join(
                    f"{site['independent_benign']['benign']['direct_union_fpr']['rate'] * 100:.2f}"
                    for site in sites
                )
            )
        lines.append("| " + " | ".join(identity + cells) + " |")
    lines += [
        "",
        "6,195 paired rows remain after disclosed source-alias, ambiguity "
        "and duplicate exclusions.",
        "These results do not establish full-capture or operational generalization. "
        "The source-addition comparisons, failure reasons, target incidental benign metrics, "
        "costs and per-family coverage remain in the machine-readable report.",
        "",
    ]
    lines.extend(comparison_tables(report))
    lines += ["", "Regenerate with `python -m scripts.verify_registered_missingness --markdown`."]
    return "\n".join(lines) + "\n"


def comparison_tables(report: dict[str, Any]) -> list[str]:
    """Descriptive paired differences, never a ranking or an independence claim."""
    sources = report["source_addition_comparisons"]
    paired = [p for p in sources if p["status"] == "paired"]
    lines = [
        "",
        "## Adding an attack source",
        "",
        f"{len(paired)}/{len(sources)} target/view/transform/site comparisons are fully paired. "
        "Each compares the combined fit to both single-source fits on identical test rows. "
        "The remaining comparisons are unevaluable, not zero effect.",
        "",
        "| Metric | Increased | Unchanged | Decreased | Min / max change (percentage points) |",
        "|---|---:|---:|---:|---:|",
    ]
    changes = [delta for p in paired for delta in p["combined_minus_single"]]
    for key in (
        "target_attack_direct",
        "target_attack_unknown",
        "target_attack_or_review",
        "independent_benign_fpr",
        "independent_benign_review",
    ):
        values = [d[key] for d in changes]
        lines.append(delta_row(key, values))

    views = report["registration"]["representation"]["views"]
    config = report["registration"]
    comparisons: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = {
        "imputation_only minus portable_intersection": [],
        "imputation_missingness minus imputation_only": [],
    }
    complete = planned = 0
    for choice in range(1, 10):
        for kind in config["representation"]["transforms"]:
            entries = [
                next(
                    c
                    for c in report["cases"]
                    if c["case_id"] == f"choice{choice:02d}-{view}-{kind}"
                )
                for view in views
            ]
            planned += 2
            if any(c["status"] != "evaluated" for c in entries):
                continue
            # All treatments must have exactly the same raw fitting and evaluation cohort.
            require(
                all(
                    c["partition_provenance"] == entries[0]["partition_provenance"] for c in entries
                ),
                "representation comparisons are not paired",
            )
            complete += 2
            for site in range(2):
                for label, (base, changed) in zip(comparisons, ((0, 1), (1, 2)), strict=True):
                    comparisons[label].append(
                        (
                            entries[base]["site_evaluations"][site],
                            entries[changed]["site_evaluations"][site],
                        )
                    )
    lines += [
        "",
        "## Packet-feature and indicator comparisons",
        "",
        f"{complete}/{planned} source-choice/transform/site triples complete all three views. "
        "Only those complete triples enter the paired differences below. "
        "Imputation versus portable also adds 60 packet features; it is not a pure "
        "imputation-method comparison. Adding indicators holds those packet features fixed.",
    ]
    for label, pairs in comparisons.items():
        lines += [
            "",
            f"### {label}",
            "",
            "| Metric | Increased | Unchanged | Decreased | Min / max change (pp) |",
            "|---|---:|---:|---:|---:|",
        ]
        for role, truth, metric in (
            ("target", "attack", "direct_suspicious_unknown"),
            ("target", "attack", "detection_or_review"),
            ("independent_benign", "benign", "direct_union_fpr"),
            ("independent_benign", "benign", "review_inclusive_rate"),
        ):
            values = [
                changed[role][truth][metric]["rate"] - base[role][truth][metric]["rate"]
                for base, changed in pairs
            ]
            lines.append(delta_row(f"{role}: {metric}", values))
    lines += [
        "",
        "An increase in benign FPR/review is worse, not an improvement. "
        "These repeated fits, source choices and site orientations are correlated; "
        "counts are descriptive, not independent replications or significance tests. "
        "No missing entry is imputed and no candidate is selected.",
    ]
    return lines


def delta_row(label: str, values: list[float]) -> str:
    if not values:
        return f"| {label} | unevaluable | — | — | — |"
    increased = sum(v > 1e-12 for v in values)
    decreased = sum(v < -1e-12 for v in values)
    return (
        f"| {label} | {increased} | {len(values) - increased - decreased} | {decreased} | "
        f"{min(values) * 100:.2f} / {max(values) * 100:.2f} |"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", type=Path)
    parser.add_argument("--markdown", action="store_true")
    args = parser.parse_args()
    report = verify(Path.cwd(), artifact_directory=args.artifact_dir)
    print(
        render_summary(report)
        if args.markdown
        else f"verified DEV2-MISSINGNESS-001: {report['coverage']}; development only"
    )


if __name__ == "__main__":
    main()
