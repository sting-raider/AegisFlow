from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from training.data.adapters import DatasetKind, load_dataset
from training.data.development import assert_development_only
from training.research.evidence import atomic_text, git_commit_from_clean_tree
from training.research.hybrid import run_held_family_hybrid_temporal


def _markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Development hybrid temporal held-family results",
        "",
        f"Experiment: `{report['experiment_id']}`",
        "",
        f"Code commit: `{report['code_commit']}`",
        "",
        f"Generated: `{report['generated_at']}`",
        "",
        "This is development-only evidence. Every reported attack family is removed from",
        "supervised fitting, anomaly fitting uses an all-benign IoT capture, thresholds use",
        "a second all-benign capture, and testing uses separate attack capture groups.",
        "",
        "| Ablation | Runs | Mean direct detection | Worst direct detection | "
        "Mean direct unknown | Worst direct unknown | Mean detection/review | "
        "Worst detection/review | Mean benign FPR | Worst benign FPR |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, values in report["summary"].items():
        lines.append(
            f"| {name} | {values['runs']} | "
            f"{values['direct_detection_recall_mean']:.5f} | "
            f"{values['direct_detection_recall_min']:.5f} | "
            f"{values['direct_suspicious_unknown_recall_mean']:.5f} | "
            f"{values['direct_suspicious_unknown_recall_min']:.5f} | "
            f"{values['detection_or_review_recall_mean']:.5f} | "
            f"{values['detection_or_review_recall_min']:.5f} | "
            f"{values['benign_fpr_mean']:.5f} | "
            f"{values['benign_fpr_max']:.5f} |"
        )
    lines.extend(["", "## Held-family runs", ""])
    for run in report["runs"]:
        full = next(
            item for item in run["ablations"] if item["ablation"] == "full_hybrid"
        )
        lines.extend(
            [
                f"### {run['held_family']}: fit {run['fit_benign_group']}, "
                f"calibrate {run['calibration_benign_group']}",
                "",
                f"Test rows `{run['test_rows']}` ({run['held_family_rows']} held-family, "
                f"{run['test_benign_rows']} benign). Full hybrid direct detection "
                f"`{full['direct_detection_recall']:.5f}`, direct suspicious-unknown "
                f"`{full['direct_suspicious_unknown_recall']:.5f}`, detection-or-review "
                f"`{full['detection_or_review_recall']:.5f}`, benign FPR "
                f"`{full['test_benign_fpr']:.5f}`.",
                "",
            ]
        )
    lines.extend(
        [
            "## Limitations",
            "",
            *[f"- {item}" for item in report["limitations"]],
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run development-only hybrid temporal held-family ablations"
    )
    parser.add_argument(
        "--source",
        nargs=3,
        action="append",
        metavar=("SOURCE_ID", "DATASET_KIND", "PATH"),
        required=True,
    )
    parser.add_argument("--temporal-source-id", required=True)
    parser.add_argument("--max-rows-per-class", type=int, default=10_000)
    parser.add_argument("--minimum-family-rows", type=int, default=20)
    parser.add_argument("--experiment-id", default="DEV-HYB-001")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path, required=True)
    parser.add_argument(
        "--frozen-manifest",
        type=Path,
        default=Path("configs/evaluation/frozen-evidence-v1.json"),
    )
    args = parser.parse_args()
    code_commit = git_commit_from_clean_tree()
    grouped: dict[str, tuple[DatasetKind, list[Path]]] = {}
    for source_id, dataset_kind, path in args.source:
        kind = cast(DatasetKind, dataset_kind)
        existing = grouped.get(source_id)
        if existing is not None and existing[0] != kind:
            raise ValueError(f"source {source_id} cannot mix dataset kinds")
        if existing is None:
            grouped[source_id] = (kind, [Path(path)])
        else:
            existing[1].append(Path(path))
    if args.temporal_source_id not in grouped:
        raise ValueError("temporal source ID must match one supplied source")
    datasets = {}
    for source_id, (dataset_kind, paths) in grouped.items():
        dataset = load_dataset(dataset_kind, paths)
        assert_development_only(dataset.provenance, args.frozen_manifest)
        datasets[source_id] = dataset
    temporal_dataset = datasets.pop(args.temporal_source_id)
    report = run_held_family_hybrid_temporal(
        datasets,
        args.temporal_source_id,
        temporal_dataset,
        max_rows_per_class=args.max_rows_per_class,
        minimum_family_rows=args.minimum_family_rows,
    )
    report["experiment_id"] = args.experiment_id
    report["code_commit"] = code_commit
    report["generated_at"] = datetime.now(UTC).isoformat()
    atomic_text(args.output, json.dumps(report, indent=2, sort_keys=True) + "\n")
    atomic_text(args.markdown_output, _markdown(report))
    print(args.output.resolve())
    print(args.markdown_output.resolve())


if __name__ == "__main__":
    main()
