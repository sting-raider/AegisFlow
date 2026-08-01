from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Any
from uuid import uuid4

import joblib
import numpy as np
import sklearn
import torch
from sklearn.base import clone
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupKFold, GroupShuffleSplit
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler, label_binarize

from packages.detection.autoencoder import DenoisingAutoencoder, reconstruction_errors
from packages.features.registry import FEATURE_NAMES, feature_schema
from packages.model_bundle.bundle import promote_bundle, sha256_file

SEED = 431
MODEL_NAME = "aegisflow-smoke"
VERSION = "0.2.0"
KNOWN_THRESHOLD = 0.72
ANOMALY_THRESHOLD = 0.70


def _dataset() -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    rng = np.random.default_rng(SEED)
    rows: list[np.ndarray] = []
    labels: list[str] = []
    groups: list[int] = []
    for group in range(12):
        for _ in range(35):
            rows.append(
                np.asarray(
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
            )
            labels.append("benign")
            groups.append(group)
        for _ in range(12):
            rows.append(
                np.asarray(
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
            )
            labels.append("port_scan")
            groups.append(group)
        for _ in range(10):
            rows.append(
                np.asarray(
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
            )
            labels.append("brute_force")
            groups.append(group)
    return np.vstack(rows), np.asarray(labels), np.asarray(groups)


def _synthetic_unknowns(held_out_benign: np.ndarray) -> np.ndarray:
    """Create non-destructive novel-behaviour fixtures outside smoke training families."""
    values = held_out_benign[: min(80, len(held_out_benign))].copy()
    values[:, 4] *= 10.0
    values[:, 7] *= 5.0
    values[:, 9] *= 10.0
    values[:, 10] *= 10.0
    values[:, 13] = 49_152.0
    values[:, 14] = values[:, 3] / np.maximum(values[:, 4], 1.0)
    values[:, 17] = values[:, 3] + values[:, 4]
    return values


def _git_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return "uncommitted"


def _train_autoencoder(benign_train: np.ndarray) -> DenoisingAutoencoder:
    torch.manual_seed(SEED)
    torch.set_num_threads(1)
    model = DenoisingAutoencoder(len(FEATURE_NAMES))
    optimizer = torch.optim.Adam(model.parameters(), lr=0.004, weight_decay=1e-5)
    clean = torch.as_tensor(benign_train, dtype=torch.float32)
    generator = torch.Generator(device="cpu").manual_seed(SEED)
    model.train()
    for _ in range(120):
        noisy = clean + torch.randn(clean.shape, generator=generator) * 0.06
        optimizer.zero_grad(set_to_none=True)
        loss = torch.mean((model(noisy) - clean) ** 2)
        loss.backward()  # type: ignore[no-untyped-call]
        optimizer.step()
    model.eval()
    return model


def _normalized_high_score(values: np.ndarray, median: float, percentile: float) -> np.ndarray:
    denominator = max(percentile - median, 1e-9)
    return np.clip(((values - median) / denominator) * ANOMALY_THRESHOLD, 0.0, 1.0)


def _normalized_low_score(values: np.ndarray, median: float, percentile: float) -> np.ndarray:
    denominator = max(median - percentile, 1e-9)
    return np.clip(((median - values) / denominator) * ANOMALY_THRESHOLD, 0.0, 1.0)


def _calibration_metrics(
    y_true: np.ndarray, probabilities: np.ndarray, classes: np.ndarray
) -> dict[str, float]:
    binary = label_binarize(y_true, classes=classes)
    if binary.shape[1] == 1:
        binary = np.column_stack((1 - binary[:, 0], binary[:, 0]))
    predicted = classes[np.argmax(probabilities, axis=1)]
    confidence = probabilities.max(axis=1)
    correct = (predicted == y_true).astype(float)
    ece = 0.0
    for lower in np.linspace(0.0, 0.9, 10):
        upper = lower + 0.1
        mask = (confidence > lower) & (confidence <= upper)
        if mask.any():
            ece += float(mask.mean()) * abs(float(correct[mask].mean() - confidence[mask].mean()))
    return {
        "multiclass_brier_score": float(np.mean(np.sum((probabilities - binary) ** 2, axis=1))),
        "expected_calibration_error_10_bins": ece,
    }


def _latency_metrics(classifier: Any, rows: np.ndarray) -> dict[str, float]:
    single_samples: list[float] = []
    for row in rows[: min(150, len(rows))]:
        started = perf_counter()
        classifier.predict_proba(row.reshape(1, -1))
        single_samples.append((perf_counter() - started) * 1000)
    batch_samples: list[float] = []
    batch = rows[: min(128, len(rows))]
    for _ in range(25):
        started = perf_counter()
        classifier.predict_proba(batch)
        batch_samples.append((perf_counter() - started) * 1000)
    return {
        "single_flow_p50_ms": float(np.percentile(single_samples, 50)),
        "single_flow_p95_ms": float(np.percentile(single_samples, 95)),
        "single_flow_p99_ms": float(np.percentile(single_samples, 99)),
        "batch_size": float(len(batch)),
        "batch_p50_ms": float(np.percentile(batch_samples, 50)),
        "batch_p95_ms": float(np.percentile(batch_samples, 95)),
        "batch_p99_ms": float(np.percentile(batch_samples, 99)),
    }


def _feature_importance(model: Any) -> list[dict[str, float | str]]:
    if hasattr(model, "feature_importances_"):
        values = np.asarray(model.feature_importances_)
    elif hasattr(model, "coef_"):
        values = np.abs(np.asarray(model.coef_)).mean(axis=0)
    else:
        return []
    order = np.argsort(values)[::-1][:10]
    return [
        {"feature": FEATURE_NAMES[int(index)], "importance": float(values[int(index)])}
        for index in order
    ]


def _atomic_replace_directory(staged: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        os.replace(staged, target)
        return
    backup = target.with_name(f".{target.name}-backup-{uuid4().hex}")
    os.replace(target, backup)
    try:
        os.replace(staged, target)
    except BaseException:
        os.replace(backup, target)
        raise
    shutil.rmtree(backup)


def train(output_root: Path) -> dict[str, Any]:
    x, y, groups = _dataset()
    train_idx, test_idx = next(
        GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=SEED).split(x, y, groups)
    )
    scaler = StandardScaler().fit(x[train_idx])
    x_train = scaler.transform(x[train_idx])
    x_test = scaler.transform(x[test_idx])
    y_train = y[train_idx]
    y_test = y[test_idx]
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
        "mlp": MLPClassifier(
            hidden_layer_sizes=(32, 16),
            alpha=0.001,
            max_iter=400,
            random_state=SEED,
        ),
    }
    scores: dict[str, float] = {}
    fitted: dict[str, Any] = {}
    for name, candidate in candidates.items():
        candidate.fit(x_train, y_train)
        fitted[name] = candidate
        scores[name] = float(f1_score(y_test, candidate.predict(x_test), average="macro"))
    selected_name = max(scores, key=scores.__getitem__)

    group_kfold = GroupKFold(n_splits=3)
    calibration_splits = list(group_kfold.split(x_train, y_train, groups[train_idx]))
    classifier = CalibratedClassifierCV(
        estimator=clone(candidates[selected_name]),
        method="sigmoid",
        cv=calibration_splits,
        n_jobs=1,
    ).fit(x_train, y_train)
    predictions = classifier.predict(x_test)
    probabilities = classifier.predict_proba(x_test)
    classes = np.asarray(classifier.classes_)
    report = classification_report(
        y_test, predictions, labels=classes, output_dict=True, zero_division=0
    )
    confusion = confusion_matrix(y_test, predictions, labels=classes)
    binary = label_binarize(y_test, classes=classes)

    benign_train = x_train[y_train == "benign"]
    benign_validation = x_test[y_test == "benign"]
    anomaly = IsolationForest(
        n_estimators=160,
        contamination="auto",
        random_state=SEED,
        n_jobs=1,
    ).fit(benign_train)
    benign_decisions = anomaly.decision_function(benign_validation)
    decision_median = float(np.percentile(benign_decisions, 50))
    decision_p03 = float(np.percentile(benign_decisions, 3))

    autoencoder = _train_autoencoder(benign_train)
    benign_errors = reconstruction_errors(autoencoder, benign_validation)
    reconstruction_p50 = float(np.percentile(benign_errors, 50))
    reconstruction_p97 = float(np.percentile(benign_errors, 97))
    reconstruction_p99 = float(np.percentile(benign_errors, 99))

    benign_if_scores = _normalized_low_score(
        anomaly.decision_function(benign_validation), decision_median, decision_p03
    )
    benign_ae_scores = _normalized_high_score(benign_errors, reconstruction_p50, reconstruction_p97)
    combined_validation_p97 = float(
        np.percentile(np.maximum(benign_if_scores, benign_ae_scores), 97)
    )
    open_set_validation_scale = ANOMALY_THRESHOLD / max(combined_validation_p97, 1e-9)

    test_if_scores = (
        _normalized_low_score(anomaly.decision_function(x_test), decision_median, decision_p03)
        * open_set_validation_scale
    )
    test_ae_scores = (
        _normalized_high_score(
            reconstruction_errors(autoencoder, x_test), reconstruction_p50, reconstruction_p97
        )
        * open_set_validation_scale
    )
    test_if_scores = np.clip(test_if_scores, 0.0, 1.0)
    test_ae_scores = np.clip(test_ae_scores, 0.0, 1.0)
    test_anomaly_scores = np.maximum(test_if_scores, test_ae_scores)
    benign_mask = y_test == "benign"
    benign_false_positive_rate = float(
        np.mean(test_anomaly_scores[benign_mask] >= ANOMALY_THRESHOLD)
    )

    raw_unknown = _synthetic_unknowns(x[test_idx][benign_mask])
    unknown_scaled = scaler.transform(raw_unknown)
    unknown_probabilities = classifier.predict_proba(unknown_scaled)
    benign_class_index = int(np.where(classes == "benign")[0][0])
    unknown_known_probability = 1.0 - unknown_probabilities[:, benign_class_index]
    unknown_if_scores = (
        _normalized_low_score(
            anomaly.decision_function(unknown_scaled), decision_median, decision_p03
        )
        * open_set_validation_scale
    )
    unknown_ae_scores = (
        _normalized_high_score(
            reconstruction_errors(autoencoder, unknown_scaled),
            reconstruction_p50,
            reconstruction_p97,
        )
        * open_set_validation_scale
    )
    unknown_if_scores = np.clip(unknown_if_scores, 0.0, 1.0)
    unknown_ae_scores = np.clip(unknown_ae_scores, 0.0, 1.0)
    unknown_scores = np.maximum(unknown_if_scores, unknown_ae_scores)
    unknown_flags = (unknown_scores >= ANOMALY_THRESHOLD) & (
        unknown_known_probability < KNOWN_THRESHOLD
    )
    known_attack_mask = y_test != "benign"
    known_probabilities = 1.0 - probabilities[:, benign_class_index]
    known_unknown_flags = (test_anomaly_scores >= ANOMALY_THRESHOLD) & (
        known_probabilities < KNOWN_THRESHOLD
    )
    known_vs_unknown_confusion = [
        [
            int(np.sum(~known_unknown_flags[known_attack_mask])),
            int(np.sum(known_unknown_flags[known_attack_mask])),
        ],
        [int(np.sum(~unknown_flags)), int(np.sum(unknown_flags))],
    ]

    metrics: dict[str, Any] = {
        "scope": "deterministic synthetic smoke test only",
        "candidate_macro_f1": scores,
        "selected": selected_name,
        "classification_report": report,
        "confusion_matrix": {"labels": classes.tolist(), "values": confusion.tolist()},
        "macro_f1": float(f1_score(y_test, predictions, average="macro")),
        "weighted_f1": float(f1_score(y_test, predictions, average="weighted")),
        "macro_pr_auc_ovr": float(average_precision_score(binary, probabilities, average="macro")),
        "macro_roc_auc_ovr": float(
            roc_auc_score(binary, probabilities, average="macro", multi_class="ovr")
        ),
        "benign_false_positive_rate": benign_false_positive_rate,
        "unknown_attack_detection_rate_synthetic": float(np.mean(unknown_flags)),
        "known_vs_unknown_confusion": {
            "labels": ["known_attack", "synthetic_unknown"],
            "predicted_columns": ["known_or_review", "suspicious_unknown"],
            "values": known_vs_unknown_confusion,
        },
        "calibration": _calibration_metrics(y_test, probabilities, classes),
        "feature_importance": _feature_importance(fitted[selected_name]),
        "latency": _latency_metrics(classifier, x_test),
        "autoencoder": {
            "trained_on_benign_rows": len(benign_train),
            "held_out_benign_rows": len(benign_validation),
            "reconstruction_error_p50": reconstruction_p50,
            "reconstruction_error_p97": reconstruction_p97,
            "reconstruction_error_p99": reconstruction_p99,
        },
        "test_rows": len(test_idx),
    }

    model_root = output_root / MODEL_NAME
    staged = model_root / f".{VERSION}-staged-{uuid4().hex}"
    target = model_root / VERSION
    staged.mkdir(parents=True, exist_ok=False)
    try:
        joblib.dump(scaler, staged / "preprocessor.joblib")
        joblib.dump(classifier, staged / "classifier.joblib")
        joblib.dump(anomaly, staged / "anomaly.joblib")
        torch.save(autoencoder.artifact(), staged / "autoencoder.pt")
        (staged / "feature_schema.json").write_text(
            json.dumps(feature_schema(), indent=2) + "\n", encoding="utf-8"
        )
        labels = {str(index): str(label) for index, label in enumerate(classes)}
        (staged / "label_mapping.json").write_text(
            json.dumps(labels, indent=2) + "\n", encoding="utf-8"
        )
        thresholds = {
            "version": "2.0.0",
            "known_threshold": KNOWN_THRESHOLD,
            "anomaly_threshold": ANOMALY_THRESHOLD,
            "isolation_decision_benign_median": decision_median,
            "isolation_decision_benign_p03": decision_p03,
            "reconstruction_error_benign_p50": reconstruction_p50,
            "reconstruction_error_benign_p97": reconstruction_p97,
            "reconstruction_error_benign_p99": reconstruction_p99,
            "open_set_validation_scale": open_set_validation_scale,
            "normalization": "validation benign p50 maps to 0; tail budget maps to 0.70",
            "selection_target": "3% held-out benign tail budget on deterministic smoke data",
        }
        (staged / "thresholds.json").write_text(
            json.dumps(thresholds, indent=2) + "\n", encoding="utf-8"
        )
        (staged / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
        (staged / "training_config.yaml").write_text(
            "\n".join(
                [
                    f"seed: {SEED}",
                    "split: source_group",
                    f"classifier: {selected_name}",
                    "calibration: sigmoid_group_kfold",
                    "anomaly_baseline: isolation_forest_benign_only",
                    "advanced_anomaly: denoising_autoencoder_benign_only",
                    "autoencoder_epochs: 120",
                    "autoencoder_noise_std: 0.06",
                    "device: cpu",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        data_manifest = {
            "name": "bundled-synthetic-smoke",
            "generated": True,
            "rows": len(x),
            "groups": len(set(groups)),
            "feature_count": len(FEATURE_NAMES),
            "seed": SEED,
            "split": {
                "strategy": "source_group",
                "train_rows": len(train_idx),
                "test_rows": len(test_idx),
                "train_groups": sorted(set(int(value) for value in groups[train_idx])),
                "test_groups": sorted(set(int(value) for value in groups[test_idx])),
            },
            "dataset_fingerprint": "synthetic-seed-431-v2",
            "not_for_performance_claims": True,
        }
        (staged / "training_data_manifest.json").write_text(
            json.dumps(data_manifest, indent=2) + "\n", encoding="utf-8"
        )
        artifact_names = [
            "preprocessor.joblib",
            "classifier.joblib",
            "anomaly.joblib",
            "autoencoder.pt",
        ]
        artifact_hashes = {name: sha256_file(staged / name) for name in artifact_names}
        manifest = {
            "bundle_schema_version": 2,
            "model_name": MODEL_NAME,
            "version": VERSION,
            "created_at": datetime.now(UTC).isoformat(),
            "git_commit": _git_commit(),
            "python_version": platform.python_version(),
            "dependency_versions": {
                "joblib": joblib.__version__,
                "numpy": np.__version__,
                "scikit_learn": sklearn.__version__,
                "torch": torch.__version__,
            },
            "feature_schema_version": "1.0.0",
            "dataset_fingerprints": ["synthetic-seed-431-v2"],
            "training_seed": SEED,
            "model_classes": classes.tolist(),
            "thresholds": thresholds,
            "calibration_method": "sigmoid calibration with grouped training-fold CV",
            "validation_metrics": {
                "macro_f1": metrics["macro_f1"],
                "weighted_f1": metrics["weighted_f1"],
                "benign_false_positive_rate": benign_false_positive_rate,
                "unknown_attack_detection_rate_synthetic": metrics[
                    "unknown_attack_detection_rate_synthetic"
                ],
            },
            "known_limitations": [
                "Synthetic smoke data is not evidence of production detection quality",
                "No packet payload or raw IP-address features are used",
                "Unknown detection identifies statistical novelty, not guaranteed zero-days",
                "Public-dataset and cross-dataset evaluation must precede production promotion",
            ],
            "artifact_hashes": artifact_hashes,
            "artifact_format": "joblib-local-trusted+torch-state-dict",
        }
        (staged / "manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
        files = sorted(path for path in staged.iterdir() if path.name != "checksums.sha256")
        (staged / "checksums.sha256").write_text(
            "".join(f"{sha256_file(path)}  {path.name}\n" for path in files),
            encoding="utf-8",
        )
        _atomic_replace_directory(staged, target)
        promote_bundle(output_root, MODEL_NAME, VERSION)
    finally:
        if staged.exists():
            shutil.rmtree(staged)
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("models/registry"))
    args = parser.parse_args()
    metrics = train(args.output)
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
