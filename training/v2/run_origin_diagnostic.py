"""Detector-v2 dataset-origin diagnostic (development evidence only).

Quantifies how strongly each candidate representation leaks environment identity by
cross-validated scenario classification. Motivated by MR2-002's observation that
scores can track environment rather than maliciousness.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_val_score

from packages.detection_v2.sequences import SEQUENCE_MAX_LENGTH
from training.v2.tensors import (
    build_dataset,
    deduplicate_records,
    load_records,
)

SEED = 20260822


def flatten_sequence(sequence: np.ndarray, mask: np.ndarray) -> np.ndarray:
    scaled: np.ndarray = sequence * mask[..., None]
    return scaled.reshape(len(scaled), -1)


def main() -> None:
    sequence_dir = Path("data/sequences_v2")
    output_dir = Path("docs/research-v2/experiments")
    report_path = output_dir / "dev2-origin-diagnostic-v1.json"
    if report_path.exists():
        raise ValueError("historical origin evidence exists; use a new registered experiment")
    records = deduplicate_records(load_records(sorted(sequence_dir.glob("*.jsonl"))))
    dataset = build_dataset(records)
    scenarios = np.asarray(dataset.scenario)
    labels = np.asarray(dataset.binary_label)

    aggregate = np.asarray(dataset.aggregate)
    state = np.asarray(dataset.state)
    sequence_flat = flatten_sequence(
        np.asarray(dataset.sequence), np.asarray(dataset.mask)
    )
    representations = {
        "v1_aggregate_schema_a": aggregate,
        "connection_state_only": state,
        "packet_sequence_flat": sequence_flat,
        "aggregate_plus_state_plus_sequence": np.concatenate(
            (aggregate, state, sequence_flat), axis=1
        ),
    }

    folds = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED)
    report: dict[str, object] = {
        "schema_version": "1.0.0",
        "experiment_id": "DEV2-ORIGIN-001",
        "generated_at": datetime.now(UTC).isoformat(),
        "seed": SEED,
        "records": len(records),
        "max_sequence_length": SEQUENCE_MAX_LENGTH,
        "task": "six-way scenario classification, 5-fold stratified CV, multinomial logreg",
        "block_threshold": 0.90,
        "status": "development_diagnostic_no_candidate_selected",
    }
    representation_results: dict[str, object] = {}
    report["representations"] = representation_results
    for name, matrix in representations.items():
        model = LogisticRegression(max_iter=3000, random_state=SEED)
        scores = cross_val_score(
            model, matrix, scenarios, cv=folds, scoring="balanced_accuracy", n_jobs=-1
        )
        entry: dict[str, object] = {
            "balanced_accuracy_mean": round(float(scores.mean()), 5),
            "balanced_accuracy_std": round(float(scores.std()), 5),
            "feature_dimension": int(matrix.shape[1]),
            "blocks_challenger_selection": bool(scores.mean() >= 0.90),
        }
        binary_model = LogisticRegression(max_iter=3000, random_state=SEED)
        binary_scores = cross_val_score(
            binary_model,
            matrix,
            labels,
            cv=folds,
            scoring="balanced_accuracy",
            n_jobs=-1,
        )
        entry["binary_task_balanced_accuracy"] = round(float(binary_scores.mean()), 5)
        representation_results[name] = entry
        print(name, entry, flush=True)

    with report_path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"wrote {report_path}")


if __name__ == "__main__":
    main()
