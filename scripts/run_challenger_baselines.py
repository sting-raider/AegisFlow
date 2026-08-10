from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from training.data.adapters import DatasetKind, load_dataset
from training.data.development import assert_development_only
from training.research.baselines import (
    DEFAULT_SUPERVISED_MODELS,
    run_cross_environment_supervised,
)


def _atomic_text(path: Path, content: str) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _git_commit_from_clean_tree() -> str:
    status = subprocess.run(
        ["git", "status", "--porcelain"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if status:
        raise ValueError("challenger experiments require a clean committed worktree")
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Development supervised baseline results",
        "",
        f"Experiment: `{report['experiment_id']}`  ",
        f"Code commit: `{report['code_commit']}`  ",
        f"Generated: `{report['generated_at']}`",
        "",
        "This is development-only evidence. It does not select, lock, or promote a model,",
        "and it does not use the frozen final reports.",
        "",
        "| Model | Mean macro F1 | Worst macro F1 | Mean benign FPR | Worst benign FPR "
        "| Mean malicious recall | Worst malicious recall |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for model, values in report["summary"].items():
        lines.append(
            f"| {model} | {values['macro_f1_mean']:.5f} | "
            f"{values['macro_f1_min']:.5f} | {values['benign_fpr_mean']:.5f} | "
            f"{values['benign_fpr_max']:.5f} | "
            f"{values['malicious_recall_mean']:.5f} | "
            f"{values['malicious_recall_min']:.5f} |"
        )
    lines.extend(
        [
            "",
            "## Cross-environment rotations",
            "",
        ]
    )
    for rotation in report["rotations"]:
        lines.extend(
            [
                f"### Test: {rotation['testing_source']}",
                "",
                f"Train sources: {', '.join(rotation['training_sources'])}. "
                f"Exact feature-row overlap: {rotation['exact_feature_row_overlap']}.",
                "",
                "| Model | Macro F1 | Benign FPR | Malicious recall | PR-AUC | ECE | Rows/s |",
                "|---|---:|---:|---:|---:|---:|---:|",
            ]
        )
        for values in rotation["models"]:
            lines.append(
                f"| {values['model']} | {values['macro_f1']:.5f} | "
                f"{values['benign_false_positive_rate']:.5f} | "
                f"{values['malicious_recall']:.5f} | "
                f"{values['pr_auc_malicious']:.5f} | {values['ece']:.5f} | "
                f"{values['throughput_rows_per_second']:.1f} |"
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
        description="Run development-only cross-environment supervised baselines"
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
        choices=DEFAULT_SUPERVISED_MODELS,
        dest="models",
    )
    parser.add_argument("--max-rows-per-class", type=int, default=10_000)
    parser.add_argument("--experiment-id", default="DEV-SUP-001")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path, required=True)
    parser.add_argument(
        "--frozen-manifest",
        type=Path,
        default=Path("configs/evaluation/frozen-evidence-v1.json"),
    )
    args = parser.parse_args()
    code_commit = _git_commit_from_clean_tree()
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
    report = run_cross_environment_supervised(
        datasets,
        models=tuple(args.models or DEFAULT_SUPERVISED_MODELS),
        max_rows_per_class=args.max_rows_per_class,
    )
    report["experiment_id"] = args.experiment_id
    report["code_commit"] = code_commit
    report["generated_at"] = datetime.now(UTC).isoformat()
    _atomic_text(args.output, json.dumps(report, indent=2, sort_keys=True) + "\n")
    _atomic_text(args.markdown_output, _markdown(report))
    print(args.output.resolve())
    print(args.markdown_output.resolve())


if __name__ == "__main__":
    main()
