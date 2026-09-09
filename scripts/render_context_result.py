"""Render deterministic DEV2-CONTEXT-001 aggregate tables."""

from __future__ import annotations

import argparse
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any

from scripts.verify_registered_context_result import REPORT_SHA256, validate_report
from training.v2.provenance import read_object, sha256_file


def _pct(value: float) -> str:
    return f"{100 * value:.2f}%"


def _delta(value: dict[str, Any]) -> str:
    low, high = value["paired_bootstrap_95"]
    return f"{_pct(value['delta'])} [{_pct(low)}, {_pct(high)}]"


def render(report: dict[str, Any]) -> str:
    coverage = report["coverage"]
    paired = report["paired_analysis"]
    lines = [
        "# DEV2-CONTEXT-001 registered result",
        "",
        f"- Execution commit: `{report['code_commit']}`",
        f"- Report SHA-256: `{REPORT_SHA256}`",
        f"- Runtime: {report['elapsed_seconds']:.2f} seconds",
        (
            f"- Coverage: {coverage['evaluated_models']}/{coverage['planned_model_entries']} "
            "models and "
            f"{coverage['evaluated_site_entries']}/{coverage['planned_site_entries']} "
            "site evaluations"
        ),
        f"- Registered conclusion: `{paired['scientific_conclusion']}`",
        "- Candidate selected: no",
        "",
        "## Paired registered comparisons",
        "",
        (
            "| Target | Site orientation | Control | Attack direct Δ (95%) | "
            "Attack detect/review Δ (95%) | Benign FPR Δ (95%) | Qualifies |"
        ),
        "|---|---|---|---:|---:|---:|:---:|",
    ]
    for entry in paired["strata"]:
        orientation = entry["orientation"]
        target = entry["target_capture"].replace("CTU-IoT-Malware-Capture-", "")
        site = (
            orientation["calibration"].replace("CTU-Honeypot-Capture-", "")
            + " → "
            + orientation["benign_test"].replace("CTU-Honeypot-Capture-", "")
        )
        endpoints = entry["endpoints"]
        lines.append(
            "| "
            + " | ".join(
                (
                    target,
                    site,
                    entry["control"],
                    _delta(endpoints["target_attack_direct"]),
                    _delta(endpoints["target_attack_or_review"]),
                    _delta(endpoints["independent_benign_direct"]),
                    "yes" if entry["benefit_qualifying"] else "no",
                )
            )
            + " |"
        )

    grouped: dict[str, dict[str, list[float]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for case in report["cases"]:
        for site in case["site_evaluations"]:
            attack = site["target"]["attack"]
            benign = site["independent_benign"]["benign"]
            values = grouped[case["view"]]
            values["direct"].append(attack["direct_detection"]["rate"])
            values["review"].append(attack["detection_or_review"]["rate"])
            values["fpr"].append(benign["direct_union_fpr"]["rate"])
            values["benign_review"].append(benign["review_inclusive_rate"]["rate"])
    lines.extend(
        [
            "",
            "## Descriptive mean across 18 site entries per view",
            "",
            "These are correlated entry means, not independent estimates.",
            "",
            (
                "| View | Attack direct | Attack detect/review | Independent benign FPR | "
                "Independent benign review |"
            ),
            "|---|---:|---:|---:|---:|",
        ]
    )
    for view in report["registration"]["representation"]["views"]:
        values = grouped[view]
        lines.append(
            f"| {view} | {_pct(statistics.fmean(values['direct']))} | "
            f"{_pct(statistics.fmean(values['review']))} | "
            f"{_pct(statistics.fmean(values['fpr']))} | "
            f"{_pct(statistics.fmean(values['benign_review']))} |"
        )
    lines.extend(
        [
            "",
            "## Decision",
            "",
            (
                "Causal context qualified in 1/6 strata versus shuffled context and "
                "0/6 versus no context. The registered rule requires at least 5/6 "
                "against each control, with every target and site orientation represented."
            ),
            "",
            (
                "Result: **NULL for detectable causal benefit in this development study.** "
                "No candidate, production claim, frozen-test access, or deployment change "
                "is authorized."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if sha256_file(args.report) != REPORT_SHA256:
        raise ValueError("context report bytes changed")
    root = Path(__file__).resolve().parents[1]
    report = read_object(args.report)
    validate_report(root, report)
    expected = render(report)
    if args.check:
        if args.output.read_text(encoding="utf-8") != expected:
            raise ValueError("context result table differs from deterministic rendering")
    else:
        if args.output.exists():
            raise FileExistsError(f"refusing to overwrite context table: {args.output}")
        args.output.write_text(expected, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
