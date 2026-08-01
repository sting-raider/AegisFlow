from __future__ import annotations

from collections import Counter
from itertools import pairwise
from time import perf_counter
from typing import Any

import numpy as np
import psutil
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import GroupShuffleSplit, StratifiedShuffleSplit
from sklearn.preprocessing import StandardScaler

from packages.features.registry import FEATURE_NAMES
from training.data.models import CanonicalDataset
from training.data.quality import train_test_overlap

SEED = 431
BENIGN_FALSE_UNKNOWN_BUDGET = 0.03


def _ece(confidence: np.ndarray, correct: np.ndarray, bins: int = 10) -> float:
    result = 0.0
    edges = np.linspace(0.0, 1.0, bins + 1)
    for lower, upper in pairwise(edges):
        selected = (confidence > lower) & (confidence <= upper)
        if selected.any():
            result += float(selected.mean()) * abs(
                float(correct[selected].mean()) - float(confidence[selected].mean())
            )
    return result


def _fit_validation_indices(
    labels: np.ndarray, groups: np.ndarray
) -> tuple[np.ndarray, np.ndarray, str]:
    indices = np.arange(len(labels))
    if len(set(map(str, groups))) >= 2:
        for offset in range(10):
            fit, validation = next(
                GroupShuffleSplit(
                    n_splits=1, test_size=0.2, random_state=SEED + offset
                ).split(indices, labels, groups)
            )
            if set(labels[fit]) == set(labels):
                return fit, validation, "source-group validation"
    counts = Counter(map(str, labels))
    if len(counts) >= 2 and min(counts.values()) >= 2:
        fit, validation = next(
            StratifiedShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED).split(
                indices, labels
            )
        )
        return fit, validation, "stratified fallback because grouped validation was infeasible"
    return indices, indices, "training-fold fallback because validation was infeasible"


def _safe_auc(
    truth: np.ndarray, probabilities: np.ndarray, classes: np.ndarray
) -> tuple[float | None, float | None]:
    selected = np.isin(truth, classes)
    known_truth = truth[selected]
    known_probabilities = probabilities[selected]
    if len(set(known_truth)) < 2:
        return None, None
    one_hot = np.zeros((len(known_truth), len(classes)), dtype=np.float64)
    class_index = {str(label): index for index, label in enumerate(classes)}
    for row, label in enumerate(known_truth):
        one_hot[row, class_index[str(label)]] = 1.0
    try:
        from sklearn.metrics import average_precision_score, roc_auc_score

        return (
            float(average_precision_score(one_hot, known_probabilities, average="macro")),
            float(
                roc_auc_score(
                    one_hot,
                    known_probabilities,
                    average="macro",
                    multi_class="ovr",
                )
            ),
        )
    except ValueError:
        return None, None


def evaluate_logistic_gate(
    training: CanonicalDataset,
    testing: CanonicalDataset,
    train_indices: np.ndarray,
    test_indices: np.ndarray,
) -> dict[str, Any]:
    x_train = training.features[train_indices]
    y_train = training.labels[train_indices]
    groups = training.groups[train_indices]
    x_test = testing.features[test_indices]
    y_test = testing.labels[test_indices]
    if not np.isfinite(x_train).all() or not np.isfinite(x_test).all():
        raise ValueError("evaluation refuses missing or infinite canonical features")
    if len(set(y_train)) < 2:
        raise ValueError("evaluation requires at least two training classes")

    fit_indices, validation_indices, validation_method = _fit_validation_indices(y_train, groups)
    scaler = StandardScaler().fit(x_train[fit_indices])
    x_fit = scaler.transform(x_train[fit_indices])
    x_validation = scaler.transform(x_train[validation_indices])
    transformed_test = scaler.transform(x_test)
    classifier = LogisticRegression(
        class_weight="balanced", max_iter=800, random_state=SEED
    ).fit(x_fit, y_train[fit_indices])
    validation_confidence = classifier.predict_proba(x_validation).max(axis=1)
    known_threshold = float(
        np.quantile(validation_confidence, BENIGN_FALSE_UNKNOWN_BUDGET)
    )

    process = psutil.Process()
    rss_before = process.memory_info().rss
    cpu_before = sum(process.cpu_times()[:2])
    batch_started = perf_counter()
    probabilities = classifier.predict_proba(transformed_test)
    batch_seconds = perf_counter() - batch_started
    cpu_seconds = sum(process.cpu_times()[:2]) - cpu_before
    rss_delta = process.memory_info().rss - rss_before
    confidence = probabilities.max(axis=1)
    class_predictions = classifier.classes_[np.argmax(probabilities, axis=1)].astype(str)
    predictions = np.where(confidence < known_threshold, "unknown", class_predictions)
    known_classes = classifier.classes_.astype(str)
    truth = np.where(np.isin(y_test, known_classes), y_test, "unknown")

    single_latency_ms: list[float] = []
    for row in transformed_test[: min(len(transformed_test), 500)]:
        started = perf_counter()
        classifier.predict_proba(row.reshape(1, -1))
        single_latency_ms.append((perf_counter() - started) * 1000.0)
    latency = np.asarray(single_latency_ms or [0.0])
    correct = predictions == truth
    report = classification_report(truth, predictions, output_dict=True, zero_division=0)
    pr_auc, roc_auc = _safe_auc(y_test, probabilities, known_classes)
    known_test = np.isin(y_test, known_classes)
    if known_test.any():
        one_hot = np.zeros((int(known_test.sum()), len(known_classes)), dtype=np.float64)
        class_index = {label: index for index, label in enumerate(known_classes)}
        for row, label in enumerate(y_test[known_test]):
            one_hot[row, class_index[str(label)]] = 1.0
        brier: float | None = float(
            np.mean(np.sum((probabilities[known_test] - one_hot) ** 2, axis=1))
        )
    else:
        brier = None
    benign = truth == "benign"
    unknown = truth == "unknown"
    benign_false_positive = (
        float(np.mean(predictions[benign] != "benign")) if benign.any() else None
    )
    unknown_detection = float(np.mean(predictions[unknown] == "unknown")) if unknown.any() else None
    timestamps = testing.timestamps[test_indices]
    valid_timestamps = timestamps[~np.isnat(timestamps)]
    replay_hours: float | None = None
    false_alerts_per_hour: float | None = None
    if len(valid_timestamps) >= 2:
        span_seconds = float(
            (valid_timestamps.max() - valid_timestamps.min()) / np.timedelta64(1, "s")
        )
        if span_seconds > 0:
            replay_hours = span_seconds / 3600.0
            false_alerts_per_hour = float(
                np.sum((truth == "benign") & (predictions != "benign")) / replay_hours
            )
    known_actual = truth != "unknown"
    known_predicted = predictions != "unknown"
    return {
        "harness": "class-weighted logistic evaluation gate",
        "seed": SEED,
        "feature_order": list(FEATURE_NAMES),
        "training_dataset": training.name,
        "testing_dataset": testing.name,
        "training_fingerprint": training.fingerprint,
        "testing_fingerprint": testing.fingerprint,
        "train_rows": len(train_indices),
        "test_rows": len(test_indices),
        "training_classes": known_classes.tolist(),
        "validation_method": validation_method,
        "unknown_confidence_threshold": known_threshold,
        "unknown_threshold_target": "3% low-confidence tail on validation data",
        "classification": report,
        "macro_f1": float(report["macro avg"]["f1-score"]),
        "weighted_f1": float(report["weighted avg"]["f1-score"]),
        "pr_auc_macro": pr_auc,
        "roc_auc_macro": roc_auc,
        "brier_multiclass": brier,
        "expected_calibration_error": _ece(confidence, correct),
        "benign_false_positive_rate": benign_false_positive,
        "unknown_detection_rate": unknown_detection,
        "known_unknown_confusion": {
            "true_known_predicted_known": int(np.sum(known_actual & known_predicted)),
            "true_known_predicted_unknown": int(np.sum(known_actual & ~known_predicted)),
            "true_unknown_predicted_known": int(np.sum(~known_actual & known_predicted)),
            "true_unknown_predicted_unknown": int(np.sum(~known_actual & ~known_predicted)),
        },
        "false_alerts_per_replay_hour": false_alerts_per_hour,
        "replay_span_hours": replay_hours,
        "latency_ms": {
            "p50_single": float(np.percentile(latency, 50)),
            "p95_single": float(np.percentile(latency, 95)),
            "p99_single": float(np.percentile(latency, 99)),
            "batch_total": batch_seconds * 1000.0,
            "end_to_end_scope": "canonical feature array through evaluation verdict only",
        },
        "flows_per_second": float(len(x_test) / max(batch_seconds, 1e-12)),
        "resource_use": {
            "process_cpu_seconds": cpu_seconds,
            "rss_delta_bytes": rss_delta,
        },
        "queue_lag": {
            "measured": False,
            "reason": "offline dataset evaluation does not use the Redis runtime",
        },
        "train_test_overlap": train_test_overlap(x_train, x_test),
    }
