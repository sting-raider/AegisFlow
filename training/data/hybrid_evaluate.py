from __future__ import annotations

from collections import Counter
from dataclasses import replace
from pathlib import Path
from time import perf_counter
from typing import Any

import numpy as np
import psutil
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import GroupShuffleSplit, StratifiedKFold, StratifiedShuffleSplit
from sklearn.preprocessing import StandardScaler

from packages.detection.autoencoder import reconstruction_errors
from packages.detection.fusion import FusionConfig
from packages.detection.hybrid import HybridPredictor
from packages.features.registry import FEATURE_NAMES
from packages.model_bundle import ModelBundle
from packages.model_bundle.calibration import EmpiricalCDF
from training.data.evaluate import _ece, _safe_auc
from training.data.models import CanonicalDataset
from training.data.quality import train_test_overlap
from training.hybrid import train_autoencoder

SEED = 431
MAX_AUTOENCODER_BENIGN_ROWS = 50_000
VERDICT_LABELS = ("benign", "known_attack", "suspicious_unknown", "needs_review")


def _fit_calibration_indices(
    labels: np.ndarray, groups: np.ndarray, timestamps: np.ndarray
) -> tuple[np.ndarray, np.ndarray, dict[str, Any]]:
    indices = np.arange(len(labels))
    unique_groups = set(map(str, groups))
    if len(unique_groups) >= 2:
        for offset in range(30):
            fit, calibration = next(
                GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED + offset).split(
                    indices, labels, groups
                )
            )
            if set(labels[fit]) == set(labels) and np.sum(labels[calibration] == "benign") >= 2:
                fit_groups = set(map(str, groups[fit]))
                calibration_groups = set(map(str, groups[calibration]))
                return (
                    fit,
                    calibration,
                    {
                        "method": "source-group calibration",
                        "fit_groups": len(fit_groups),
                        "calibration_groups": len(calibration_groups),
                        "group_overlap": len(fit_groups & calibration_groups),
                    },
                )
    if len(timestamps) == len(labels) and not np.isnat(timestamps).any():
        ordered = np.argsort(timestamps, kind="stable")
        boundary = int(len(ordered) * 0.8)
        fit = ordered[:boundary]
        calibration = ordered[boundary:]
        if (
            len(fit)
            and len(calibration)
            and set(labels[fit]) == set(labels)
            and np.sum(labels[calibration] == "benign") >= 2
        ):
            return (
                fit,
                calibration,
                {
                    "method": "chronological calibration; grouped calibration infeasible",
                    "fit_groups": len(set(map(str, groups[fit]))),
                    "calibration_groups": len(set(map(str, groups[calibration]))),
                    "group_overlap": len(
                        set(map(str, groups[fit])) & set(map(str, groups[calibration]))
                    ),
                    "fit_end": str(timestamps[fit].max()),
                    "calibration_start": str(timestamps[calibration].min()),
                },
            )
    counts = Counter(map(str, labels))
    if len(counts) >= 2 and min(counts.values()) >= 3:
        fit, calibration = next(
            StratifiedShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED).split(
                indices, labels
            )
        )
        if np.sum(labels[calibration] == "benign") >= 2:
            return (
                fit,
                calibration,
                {
                    "method": "stratified row fallback; grouped calibration infeasible",
                    "fit_groups": len(set(map(str, groups[fit]))),
                    "calibration_groups": len(set(map(str, groups[calibration]))),
                    "group_overlap": len(
                        set(map(str, groups[fit])) & set(map(str, groups[calibration]))
                    ),
                },
            )
    raise ValueError(
        "exact hybrid evaluation requires a disjoint calibration fold with benign rows"
    )


def _fit_bundle(
    dataset: CanonicalDataset,
    train_indices: np.ndarray,
    deployed_bundle: ModelBundle,
) -> tuple[ModelBundle, dict[str, Any]]:
    outer_features = dataset.features[train_indices]
    outer_labels = dataset.labels[train_indices]
    outer_groups = dataset.groups[train_indices]
    outer_timestamps = dataset.timestamps[train_indices]
    if not np.all(np.isfinite(outer_features)):
        raise ValueError("exact hybrid training refuses non-finite features")
    if "benign" not in set(outer_labels):
        raise ValueError("exact hybrid training requires benign rows")
    if len(set(outer_labels)) < 2:
        raise ValueError("exact hybrid training requires benign and attack classes")
    fit_indices, calibration_indices, calibration_split = _fit_calibration_indices(
        outer_labels, outer_groups, outer_timestamps
    )
    x_fit_raw = outer_features[fit_indices]
    y_fit = outer_labels[fit_indices]
    x_calibration_raw = outer_features[calibration_indices]
    y_calibration = outer_labels[calibration_indices]
    scaler = StandardScaler().fit(x_fit_raw)
    x_fit = scaler.transform(x_fit_raw)
    x_calibration = scaler.transform(x_calibration_raw)

    class_counts = Counter(map(str, y_fit))
    calibration_folds = min(3, min(class_counts.values()))
    if calibration_folds < 2:
        raise ValueError("classifier calibration requires at least two rows per training class")
    classifier = CalibratedClassifierCV(
        estimator=LogisticRegression(class_weight="balanced", max_iter=1_500, random_state=SEED),
        method="sigmoid",
        cv=StratifiedKFold(n_splits=calibration_folds, shuffle=True, random_state=SEED),
        n_jobs=1,
    ).fit(x_fit, y_fit)

    benign_fit = x_fit[y_fit == "benign"]
    if len(benign_fit) > MAX_AUTOENCODER_BENIGN_ROWS:
        selected = np.random.default_rng(SEED).choice(
            len(benign_fit), MAX_AUTOENCODER_BENIGN_ROWS, replace=False
        )
        autoencoder_fit = benign_fit[np.sort(selected)]
    else:
        autoencoder_fit = benign_fit
    benign_calibration = x_calibration[y_calibration == "benign"]
    anomaly = IsolationForest(
        n_estimators=160,
        contamination="auto",
        random_state=SEED,
        n_jobs=1,
    ).fit(benign_fit)
    autoencoder = train_autoencoder(autoencoder_fit, seed=SEED)
    benign_decisions = anomaly.decision_function(benign_calibration)
    decision_median = float(np.percentile(benign_decisions, 50))
    decision_p03 = float(np.percentile(benign_decisions, 3))
    benign_errors = reconstruction_errors(autoencoder, benign_calibration)
    reconstruction_p50 = float(np.percentile(benign_errors, 50))
    reconstruction_p97 = float(np.percentile(benign_errors, 97))
    reconstruction_p99 = float(np.percentile(benign_errors, 99))

    deployed_fusion = FusionConfig.from_mapping(deployed_bundle.thresholds)
    normalization_tail = float(
        deployed_bundle.thresholds.get("anomaly_normalization_tail_score", 0.70)
    )
    isolation = _normalized_low(benign_decisions, decision_median, decision_p03, normalization_tail)
    reconstruction = _normalized_high(
        benign_errors, reconstruction_p50, reconstruction_p97, normalization_tail
    )
    combined_p97 = float(np.percentile(np.maximum(isolation, reconstruction), 97))
    validation_scale = normalization_tail / max(combined_p97, 1e-9)
    calibrated_scores = np.maximum(
        np.clip(isolation * validation_scale, 0.0, 1.0),
        np.clip(reconstruction * validation_scale, 0.0, 1.0),
    )
    empirical_cdf = EmpiricalCDF.fit(calibrated_scores)
    thresholds: dict[str, Any] = {
        **deployed_fusion.to_dict(),
        "anomaly_normalization_tail_score": normalization_tail,
        "isolation_decision_benign_median": decision_median,
        "isolation_decision_benign_p03": decision_p03,
        "reconstruction_error_benign_p50": reconstruction_p50,
        "reconstruction_error_benign_p97": reconstruction_p97,
        "reconstruction_error_benign_p99": reconstruction_p99,
        "open_set_validation_scale": validation_scale,
    }
    classes = [str(value) for value in classifier.classes_]
    bundle = ModelBundle(
        root=Path("<in-memory-exact-hybrid-evaluation>"),
        manifest={
            "version": f"evaluation-{dataset.fingerprint[:12]}",
            "bundle_schema_version": 3,
            "feature_schema_version": "1.0.0",
            "model_classes": classes,
        },
        thresholds=thresholds,
        labels={str(index): label for index, label in enumerate(classes)},
        preprocessor=scaler,
        classifier=classifier,
        anomaly=anomaly,
        autoencoder=autoencoder,
        anomaly_calibration=empirical_cdf,
    )
    return bundle, {
        "outer_train_rows": len(train_indices),
        "fit_rows": len(fit_indices),
        "calibration_rows": len(calibration_indices),
        "fit_benign_rows": len(benign_fit),
        "autoencoder_fit_benign_rows": len(autoencoder_fit),
        "calibration_benign_rows": len(benign_calibration),
        "calibration_cdf_knots": len(empirical_cdf.values),
        "classifier_family": "sigmoid-calibrated class-weighted logistic regression",
        "anomaly_models": ["IsolationForest", "CPU denoising autoencoder"],
        "fusion_version": deployed_fusion.version,
        "calibration_split": calibration_split,
    }


def evaluate_hybrid_gate(
    training: CanonicalDataset,
    testing: CanonicalDataset,
    train_indices: np.ndarray,
    test_indices: np.ndarray,
    deployed_bundle: ModelBundle,
) -> dict[str, Any]:
    x_test = testing.features[test_indices]
    y_test = testing.labels[test_indices]
    if not np.all(np.isfinite(x_test)):
        raise ValueError("exact hybrid evaluation refuses non-finite test features")
    process = psutil.Process()
    rss_before_fit = process.memory_info().rss
    cpu_before_fit = sum(process.cpu_times()[:2])
    fit_started = perf_counter()
    bundle, fit_manifest = _fit_bundle(training, train_indices, deployed_bundle)
    fit_seconds = perf_counter() - fit_started
    fit_cpu_seconds = sum(process.cpu_times()[:2]) - cpu_before_fit

    predictor = HybridPredictor(bundle)
    rss_before_inference = process.memory_info().rss
    cpu_before_inference = sum(process.cpu_times()[:2])
    batch_started = perf_counter()
    result = predictor.predict(x_test)
    batch_seconds = perf_counter() - batch_started
    inference_cpu_seconds = sum(process.cpu_times()[:2]) - cpu_before_inference
    rss_after = process.memory_info().rss

    known_classes = set(result.classes)
    truth = np.asarray(
        [
            "benign"
            if label == "benign"
            else "known_attack"
            if label in known_classes
            else "suspicious_unknown"
            for label in y_test
        ]
    )
    predictions = np.asarray([outcome.verdict.value for outcome in result.outcomes])
    report = classification_report(
        truth,
        predictions,
        labels=list(VERDICT_LABELS),
        output_dict=True,
        zero_division=0,
    )
    observed_report = classification_report(truth, predictions, output_dict=True, zero_division=0)

    baseline_bundle = replace(
        bundle,
        thresholds={
            **bundle.thresholds,
            **FusionConfig(version="3.0.0-baseline").to_dict(),
        },
    )
    baseline_result = HybridPredictor(baseline_bundle).predict(x_test)
    baseline_predictions = np.asarray(
        [outcome.verdict.value for outcome in baseline_result.outcomes]
    )
    baseline_report = classification_report(
        truth,
        baseline_predictions,
        labels=list(VERDICT_LABELS),
        output_dict=True,
        zero_division=0,
    )
    baseline_observed_report = classification_report(
        truth, baseline_predictions, output_dict=True, zero_division=0
    )

    known_mask = np.isin(y_test, result.classes)
    family_predictions = np.asarray(result.classes)[np.argmax(result.probabilities, axis=1)]
    family_report = (
        classification_report(
            y_test[known_mask], family_predictions[known_mask], output_dict=True, zero_division=0
        )
        if known_mask.any()
        else None
    )
    pr_auc, roc_auc = _safe_auc(y_test, result.probabilities, np.asarray(result.classes))
    brier = _multiclass_brier(y_test, result.probabilities, result.classes)
    known_correct = family_predictions[known_mask] == y_test[known_mask]
    ece = _ece(result.confidences[known_mask], known_correct) if known_mask.any() else None
    benign = truth == "benign"
    unknown = truth == "suspicious_unknown"
    benign_false_positive = (
        float(np.mean(predictions[benign] != "benign")) if benign.any() else None
    )
    suspicious_unknown_rate = (
        float(np.mean(predictions[unknown] == "suspicious_unknown")) if unknown.any() else None
    )
    unknown_review_rate = (
        float(np.mean(np.isin(predictions[unknown], ["suspicious_unknown", "needs_review"])))
        if unknown.any()
        else None
    )
    timestamps = testing.timestamps[test_indices]
    false_alerts_per_hour, replay_hours = _false_alert_rate(truth, predictions, timestamps)
    single_latency = _single_latency(predictor, x_test)
    confusion = confusion_matrix(truth, predictions, labels=list(VERDICT_LABELS))
    known_truth = truth != "suspicious_unknown"
    predicted_unknown = predictions == "suspicious_unknown"
    fixed_macro_f1 = float(report["macro avg"]["f1-score"])
    observed_macro_f1 = float(observed_report["macro avg"]["f1-score"])
    weighted_f1 = float(report["weighted avg"]["f1-score"])
    overlap_report = train_test_overlap(
        training.features[train_indices], testing.features[test_indices]
    )
    readiness_gate = _readiness_gate(
        observed_macro_f1=observed_macro_f1,
        benign_false_positive_rate=benign_false_positive,
        suspicious_unknown_detection_rate=suspicious_unknown_rate,
        unknown_detection_or_review_rate=unknown_review_rate,
        expected_calibration_error=ece,
        false_alerts_per_replay_hour=false_alerts_per_hour,
        overlap_fraction=float(overlap_report["overlap_fraction"]),
    )
    return {
        "harness": "exact deployed hybrid pipeline",
        "shared_inference_path": "packages.detection.hybrid.HybridPredictor",
        "seed": SEED,
        "feature_order": list(FEATURE_NAMES),
        "training_dataset": training.name,
        "testing_dataset": testing.name,
        "training_fingerprint": training.fingerprint,
        "testing_fingerprint": testing.fingerprint,
        "train_rows": len(train_indices),
        "test_rows": len(test_indices),
        "fit_manifest": fit_manifest,
        "training_classes": list(result.classes),
        "unknown_test_families": sorted(set(map(str, y_test)) - known_classes),
        "verdict_classification": report,
        "verdict_confusion_matrix": {
            "labels": list(VERDICT_LABELS),
            "values": confusion.tolist(),
        },
        "verdict_counts": {label: int(np.sum(predictions == label)) for label in VERDICT_LABELS},
        "macro_f1": fixed_macro_f1,
        "observed_label_macro_f1": observed_macro_f1,
        "weighted_f1": weighted_f1,
        "known_family_classification": family_report,
        "pr_auc_macro": pr_auc,
        "roc_auc_macro": roc_auc,
        "brier_multiclass_known_families": brier,
        "expected_calibration_error_known_families": ece,
        "benign_false_positive_rate": benign_false_positive,
        "suspicious_unknown_detection_rate": suspicious_unknown_rate,
        "unknown_detection_or_review_rate": unknown_review_rate,
        "known_unknown_confusion": {
            "true_known_predicted_known": int(np.sum(known_truth & ~predicted_unknown)),
            "true_known_predicted_unknown": int(np.sum(known_truth & predicted_unknown)),
            "true_unknown_predicted_known": int(np.sum(~known_truth & ~predicted_unknown)),
            "true_unknown_predicted_unknown": int(np.sum(~known_truth & predicted_unknown)),
            "needs_review": int(np.sum(predictions == "needs_review")),
        },
        "false_alerts_per_replay_hour": false_alerts_per_hour,
        "replay_span_hours": replay_hours,
        "anomaly_percentile_summary": _percentiles(result.anomaly_percentiles),
        "fusion_comparison": {
            "baseline_config": FusionConfig(version="3.0.0-baseline").to_dict(),
            "deployed_config": predictor.fusion.to_dict(),
            "baseline_macro_f1": float(baseline_report["macro avg"]["f1-score"]),
            "deployed_macro_f1": float(report["macro avg"]["f1-score"]),
            "baseline_observed_label_macro_f1": float(
                baseline_observed_report["macro avg"]["f1-score"]
            ),
            "deployed_observed_label_macro_f1": float(
                observed_report["macro avg"]["f1-score"]
            ),
            "macro_f1_label_scope": list(VERDICT_LABELS),
        },
        "latency_ms": {
            **single_latency,
            "batch_total": batch_seconds * 1000.0,
            "batch_per_flow": batch_seconds * 1000.0 / max(len(x_test), 1),
            "end_to_end_scope": "canonical feature array through exact hybrid verdict",
        },
        "flows_per_second": float(len(x_test) / max(batch_seconds, 1e-12)),
        "resource_use": {
            "fit_wall_seconds": fit_seconds,
            "fit_cpu_seconds": fit_cpu_seconds,
            "inference_cpu_seconds": inference_cpu_seconds,
            "rss_delta_bytes": rss_after - rss_before_fit,
            "inference_rss_delta_bytes": rss_after - rss_before_inference,
        },
        "queue_lag": {
            "measured": False,
            "reason": "offline dataset evaluation does not use the Redis runtime",
        },
        "train_test_overlap": overlap_report,
        "readiness_gate": readiness_gate,
        "limitations": [
            "Dataset adapters may approximate source fields documented in adapter_notes.",
            "No signature or rolling contextual evidence is synthesized for CSV rows.",
            "needs_review is a detector decision state, not a ground-truth dataset class.",
        ],
    }


def _readiness_gate(
    *,
    observed_macro_f1: float,
    benign_false_positive_rate: float | None,
    suspicious_unknown_detection_rate: float | None,
    unknown_detection_or_review_rate: float | None,
    expected_calibration_error: float | None,
    false_alerts_per_replay_hour: float | None,
    overlap_fraction: float,
) -> dict[str, Any]:
    criteria = {
        "observed_label_macro_f1": _minimum_criterion(observed_macro_f1, 0.60),
        "benign_false_positive_rate": _maximum_criterion(
            benign_false_positive_rate, 0.01
        ),
        "suspicious_unknown_detection_rate": _minimum_criterion(
            suspicious_unknown_detection_rate, 0.50
        ),
        "unknown_detection_or_review_rate": _minimum_criterion(
            unknown_detection_or_review_rate, 0.80
        ),
        "expected_calibration_error": _maximum_criterion(
            expected_calibration_error, 0.10
        ),
        "false_alerts_per_replay_hour": _maximum_criterion(
            false_alerts_per_replay_hour, 10.0
        ),
        "train_test_overlap_fraction": _maximum_criterion(overlap_fraction, 0.01),
    }
    applicable = [item for item in criteria.values() if item["status"] != "not_applicable"]
    passed = bool(applicable) and all(item["status"] == "pass" for item in applicable)
    return {
        "status": "pass" if passed else "fail",
        "automatic_promotion_allowed": False,
        "criteria": criteria,
        "policy": (
            "A single report can block a candidate but cannot authorize promotion; "
            "all required split modes and human review remain mandatory."
        ),
    }


def _minimum_criterion(value: float | None, minimum: float) -> dict[str, Any]:
    return {
        "value": value,
        "operator": ">=",
        "threshold": minimum,
        "status": "not_applicable" if value is None else "pass" if value >= minimum else "fail",
    }


def _maximum_criterion(value: float | None, maximum: float) -> dict[str, Any]:
    return {
        "value": value,
        "operator": "<=",
        "threshold": maximum,
        "status": "not_applicable" if value is None else "pass" if value <= maximum else "fail",
    }


def _normalized_low(values: np.ndarray, median: float, tail: float, target: float) -> np.ndarray:
    return np.clip(((median - values) / max(median - tail, 1e-9)) * target, 0.0, 1.0)


def _normalized_high(values: np.ndarray, median: float, tail: float, target: float) -> np.ndarray:
    return np.clip(((values - median) / max(tail - median, 1e-9)) * target, 0.0, 1.0)


def _multiclass_brier(
    truth: np.ndarray, probabilities: np.ndarray, classes: tuple[str, ...]
) -> float | None:
    selected = np.isin(truth, classes)
    if not selected.any():
        return None
    one_hot = np.zeros((int(selected.sum()), len(classes)), dtype=np.float64)
    indices = {label: index for index, label in enumerate(classes)}
    for row, label in enumerate(truth[selected]):
        one_hot[row, indices[str(label)]] = 1.0
    return float(np.mean(np.sum((probabilities[selected] - one_hot) ** 2, axis=1)))


def _false_alert_rate(
    truth: np.ndarray, predictions: np.ndarray, timestamps: np.ndarray
) -> tuple[float | None, float | None]:
    valid = timestamps[~np.isnat(timestamps)]
    if len(valid) < 2:
        return None, None
    span_seconds = float((valid.max() - valid.min()) / np.timedelta64(1, "s"))
    if span_seconds <= 0:
        return None, None
    hours = span_seconds / 3600.0
    false_alerts = np.sum((truth == "benign") & (predictions != "benign"))
    return float(false_alerts / hours), hours


def _single_latency(predictor: HybridPredictor, features: np.ndarray) -> dict[str, float]:
    values: list[float] = []
    for row in features[: min(len(features), 200)]:
        started = perf_counter()
        predictor.predict(row)
        values.append((perf_counter() - started) * 1000.0)
    samples = np.asarray(values or [0.0])
    return {
        "p50_single": float(np.percentile(samples, 50)),
        "p95_single": float(np.percentile(samples, 95)),
        "p99_single": float(np.percentile(samples, 99)),
    }


def _percentiles(values: np.ndarray) -> dict[str, float]:
    return {
        "p50": float(np.percentile(values, 50)),
        "p95": float(np.percentile(values, 95)),
        "p99": float(np.percentile(values, 99)),
    }
