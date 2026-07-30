from __future__ import annotations

import argparse
import json
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, f1_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler

from packages.features.registry import FEATURE_NAMES, feature_schema
from packages.model_bundle.bundle import sha256_file

SEED = 431
MODEL_NAME = "aegisflow-smoke"
VERSION = "0.1.0"


def _dataset() -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    rng = np.random.default_rng(SEED)
    rows: list[np.ndarray] = []
    labels: list[str] = []
    groups: list[int] = []
    for group in range(12):
        for _ in range(35):
            base = np.asarray(
                [
                    rng.uniform(20, 1500),
                    rng.uniform(2, 30),
                    rng.uniform(1, 25),
                    rng.uniform(300, 18_000),
                    rng.uniform(200, 22_000),
                    rng.uniform(2, 80),
                    rng.uniform(500, 80_000),
                    rng.uniform(60, 900),
                    rng.uniform(5, 250),
                    rng.uniform(2, 300),
                    rng.uniform(1, 100),
                    rng.uniform(0, 3),
                    rng.uniform(0, 1),
                    rng.choice([53, 80, 123, 443, 993]),
                    rng.uniform(0.3, 3),
                    rng.uniform(0, 2),
                    rng.uniform(3, 55),
                    rng.uniform(500, 40_000),
                ]
            )
            rows.append(base)
            labels.append("benign")
            groups.append(group)
        for _ in range(12):
            scan = np.asarray(
                [
                    rng.uniform(100, 3000),
                    rng.uniform(30, 180),
                    rng.uniform(0, 5),
                    rng.uniform(1500, 15_000),
                    rng.uniform(0, 1200),
                    rng.uniform(80, 850),
                    rng.uniform(4_000, 200_000),
                    rng.uniform(40, 120),
                    rng.uniform(1, 35),
                    rng.uniform(0.2, 8),
                    rng.uniform(0.1, 4),
                    rng.uniform(25, 180),
                    rng.uniform(2, 20),
                    rng.uniform(1, 65_535),
                    rng.uniform(4, 80),
                    rng.uniform(8, 100),
                    rng.uniform(30, 185),
                    rng.uniform(1500, 16_000),
                ]
            )
            rows.append(scan)
            labels.append("port_scan")
            groups.append(group)
        for _ in range(10):
            brute = np.asarray(
                [
                    rng.uniform(500, 12_000),
                    rng.uniform(80, 350),
                    rng.uniform(40, 250),
                    rng.uniform(8_000, 80_000),
                    rng.uniform(5_000, 100_000),
                    rng.uniform(25, 250),
                    rng.uniform(3_000, 100_000),
                    rng.uniform(60, 700),
                    rng.uniform(20, 300),
                    rng.uniform(1, 80),
                    rng.uniform(1, 50),
                    rng.uniform(30, 220),
                    rng.uniform(8, 90),
                    rng.choice([21, 22, 23, 3389, 5900]),
                    rng.uniform(0.2, 4),
                    rng.uniform(1, 8),
                    rng.uniform(120, 600),
                    rng.uniform(15_000, 180_000),
                ]
            )
            rows.append(brute)
            labels.append("brute_force")
            groups.append(group)
    return np.vstack(rows), np.asarray(labels), np.asarray(groups)


def _git_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return "uncommitted"


def train(output_root: Path) -> dict[str, Any]:
    x, y, groups = _dataset()
    train_idx, test_idx = next(
        GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=SEED).split(x, y, groups)
    )
    scaler = StandardScaler().fit(x[train_idx])
    x_train = scaler.transform(x[train_idx])
    x_test = scaler.transform(x[test_idx])
    candidates = {
        "logistic_regression": LogisticRegression(
            max_iter=1500, class_weight="balanced", random_state=SEED
        ),
        "random_forest": RandomForestClassifier(
            n_estimators=120,
            max_depth=10,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=SEED,
            n_jobs=1,
        ),
    }
    scores: dict[str, float] = {}
    fitted: dict[str, Any] = {}
    for name, classifier in candidates.items():
        classifier.fit(x_train, y[train_idx])
        fitted[name] = classifier
        scores[name] = float(f1_score(y[test_idx], classifier.predict(x_test), average="macro"))
    selected_name = max(scores, key=lambda name: scores[name])
    classifier = fitted[selected_name]
    report = classification_report(
        y[test_idx], classifier.predict(x_test), output_dict=True, zero_division=0
    )
    benign = x_train[y[train_idx] == "benign"]
    anomaly = IsolationForest(
        n_estimators=160, contamination=0.03, random_state=SEED, n_jobs=1
    ).fit(benign)
    benign_decisions = anomaly.decision_function(benign)
    center = float(np.quantile(benign_decisions, 0.03))
    scale = float(max(np.std(benign_decisions), 0.02))

    root = output_root / MODEL_NAME / VERSION
    root.mkdir(parents=True, exist_ok=True)
    joblib.dump(scaler, root / "preprocessor.joblib")
    joblib.dump(classifier, root / "classifier.joblib")
    joblib.dump(anomaly, root / "anomaly.joblib")
    (root / "feature_schema.json").write_text(
        json.dumps(feature_schema(), indent=2) + "\n", encoding="utf-8"
    )
    labels = {str(i): label for i, label in enumerate(classifier.classes_)}
    (root / "label_mapping.json").write_text(json.dumps(labels, indent=2) + "\n", encoding="utf-8")
    thresholds = {
        "version": "1.0.0",
        "known_threshold": 0.72,
        "anomaly_threshold": 0.70,
        "anomaly_decision_center": center,
        "anomaly_decision_scale": scale,
        "selection_target": "smoke grouped-split macro F1; thresholds are demo baselines",
    }
    (root / "thresholds.json").write_text(json.dumps(thresholds, indent=2) + "\n", encoding="utf-8")
    metrics = {
        "scope": "synthetic smoke test only",
        "candidate_macro_f1": scores,
        "selected": selected_name,
        "classification_report": report,
        "test_rows": len(test_idx),
    }
    (root / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    (root / "training_config.yaml").write_text(
        f"seed: {SEED}\nsplit: source_group\nmodel: {selected_name}\nanomaly: isolation_forest\n",
        encoding="utf-8",
    )
    data_manifest = {
        "name": "bundled-synthetic-smoke",
        "generated": True,
        "rows": len(x),
        "groups": len(set(groups)),
        "feature_count": len(FEATURE_NAMES),
        "seed": SEED,
        "not_for_performance_claims": True,
    }
    (root / "training_data_manifest.json").write_text(
        json.dumps(data_manifest, indent=2) + "\n", encoding="utf-8"
    )
    manifest = {
        "model_name": MODEL_NAME,
        "version": VERSION,
        "created_at": datetime.now(UTC).isoformat(),
        "git_commit": _git_commit(),
        "python_version": platform.python_version(),
        "sklearn_version": sklearn.__version__,
        "feature_schema_version": "1.0.0",
        "dataset_fingerprints": ["synthetic-seed-431-v1"],
        "training_seed": SEED,
        "model_classes": list(classifier.classes_),
        "thresholds": thresholds,
        "calibration_method": "native probabilities; smoke only",
        "validation_metrics": {"macro_f1": scores[selected_name]},
        "known_limitations": [
            "Synthetic smoke data is not evidence of production detection quality",
            "No payload features",
            "Isolation Forest is a baseline",
        ],
        "artifact_format": "joblib-local-trusted",
    }
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    files = sorted(path for path in root.iterdir() if path.name != "checksums.sha256")
    (root / "checksums.sha256").write_text(
        "".join(f"{sha256_file(path)}  {path.name}\n" for path in files), encoding="utf-8"
    )
    pointer = output_root / MODEL_NAME / "production.json"
    pointer.write_text(
        json.dumps({"version": VERSION, "updated_at": datetime.now(UTC).isoformat()}, indent=2)
        + "\n",
        encoding="utf-8",
    )
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("models/registry"))
    args = parser.parse_args()
    metrics = train(args.output)
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
