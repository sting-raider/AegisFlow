from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from training.data.adapters import DatasetKind, load_dataset
from training.data.development import assert_development_only
from training.research.anomaly import (
    DEFAULT_ANOMALY_MODELS,
    run_cross_environment_anomaly_baselines,
)
from training.research.evidence import atomic_text, git_commit_from_clean_tree


def _markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Development anomaly/open-set baseline results",
        "",
        f"Experiment: `{report['experiment_id']}`",
        "",
        f"Code commit: `{report['code_commit']}`",
        "",
        f"Generated: `{report['generated_at']}`",
        "",
        "This is development-only evidence. One environment supplies benign fit data, a",
        "second supplies benign calibration, and the third is completely held out. No",
        "attack family enters anomaly fit or calibration.",
        "",
        "| Model | Complete | Failed | Mean direct unknown recall | Worst direct recall | "
        "Mean detection-or-review | Worst detection-or-review | Mean benign FPR | "
        "Worst benign FPR |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for model, values in report["summary"].items():
        if not values["completed_runs"]:
            lines.append(
                f"| {model} | 0 | {values['failed_runs']} | n/a | n/a | n/a | n/a | n/a | n/a |"
            )
            continue
        lines.append(
            f"| {model} | {values['completed_runs']} | {values['failed_runs']} | "
            f"{values['direct_unknown_recall_mean']:.5f} | "
            f"{values['direct_unknown_recall_min']:.5f} | "
            f"{values['detection_or_review_mean']:.5f} | "
            f"{values['detection_or_review_min']:.5f} | "
            f"{values['benign_fpr_mean']:.5f} | {values['benign_fpr_max']:.5f} |"
        )
    lines.extend(["", "## Runs", ""])
    for values in report["runs"]:
        title = (
            f"{values['model']}: fit {values['fit_source']}, calibrate "
            f"{values['calibration_source']}, test {values['testing_source']}"
        )
        lines.append(f"### {title}")
        lines.append("")
        if values["status"] != "complete":
            lines.append(
                f"Failed visibly: `{values['error_type']}` — {values['error']}"
            )
        else:
            lines.append(
                f"Direct recall `{values['direct_suspicious_unknown_recall']:.5f}`; "
                f"detection-or-review `{values['detection_or_review_recall']:.5f}`; "
                f"benign FPR `{values['test_benign_false_positive_rate']:.5f}`; "
                f"PR-AUC `{values['pr_auc_malicious']:.5f}`."
            )
        lines.append("")
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
        description="Run three-way development-only anomaly/open-set baselines"
    )
    parser.add_argument(
        "--source",
        nargs=3,
        action="append",
        metavar=("SOURCE_ID", "DATASET_KIND", "PATH"),
        required=True,
    )
    parser.add_argument(
        "--model",
        action="append",
        choices=DEFAULT_ANOMALY_MODELS,
        dest="models",
    )
    parser.add_argument("--max-rows-per-class", type=int, default=10_000)
    parser.add_argument("--experiment-id", default="DEV-ANO-001")
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
    datasets = {}
    for source_id, (dataset_kind, paths) in grouped.items():
        dataset = load_dataset(dataset_kind, paths)
        assert_development_only(dataset.provenance, args.frozen_manifest)
        datasets[source_id] = dataset
    report = run_cross_environment_anomaly_baselines(
        datasets,
        models=tuple(args.models or DEFAULT_ANOMALY_MODELS),
        max_rows_per_class=args.max_rows_per_class,
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
