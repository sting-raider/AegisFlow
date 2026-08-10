from __future__ import annotations

import hashlib
from dataclasses import dataclass
from itertools import pairwise
from time import perf_counter
from typing import Any

import numpy as np
import psutil
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    brier_score_loss,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    roc_auc_score,
)
from sklearn.neural_network import MLPClassifier

from packages.features.research import (
    PORTABLE_FEATURE_NAMES,
    PORTABLE_NUMERICAL_CORE_FEATURE_NAMES,
    PORTABLE_SCHEMA_VERSION,
)
from training.data.models import CanonicalDataset
from training.features import RobustResearchPreprocessor

RESEARCH_SEED = 431
DEFAULT_SUPERVISED_MODELS = (
    "logistic_regression",
    "calibrated_random_forest",
    "hist_gradient_boosting",
    "compact_mlp",
)


@dataclass(frozen=True)
class PreparedResearchSource:
    source_id: str
    matrix: np.ndarray
    binary_labels: np.ndarray
    family_labels: np.ndarray
    groups: np.ndarray
    timestamps: np.ndarray
    manifest: dict[str, Any]


def _stable_offset(value: str) -> int:
    return int.from_bytes(hashlib.sha256(value.encode("utf-8")).digest()[:4], "big")


def _indices_sha256(indices: np.ndarray) -> str:
    return hashlib.sha256(indices.astype("<i8", copy=False).tobytes()).hexdigest()


def _prepare_source(
    source_id: str,
    dataset: CanonicalDataset,
    *,
    max_rows_per_class: int,
    seed: int,
) -> PreparedResearchSource:
    if dataset.portable_features is None:
        raise ValueError(f"source {source_id} does not provide research Schema A")
    feature_indices = np.asarray(
        [PORTABLE_FEATURE_NAMES.index(name) for name in PORTABLE_NUMERICAL_CORE_FEATURE_NAMES]
    )
    matrix = dataset.portable_features[:, feature_indices]
    binary = np.asarray(dataset.labels != "benign", dtype=np.int8)
    selected_parts: list[np.ndarray] = []
    generator = np.random.default_rng(seed + _stable_offset(source_id))
    for target in (0, 1):
        candidates = np.flatnonzero(binary == target)
        if not len(candidates):
            raise ValueError(f"source {source_id} requires benign and malicious rows")
        if len(candidates) > max_rows_per_class:
            candidates = np.sort(
                generator.choice(candidates, size=max_rows_per_class, replace=False)
            )
        selected_parts.append(candidates)
    selected = np.sort(np.concatenate(selected_parts)).astype(np.int64)
    sampled_matrix = matrix[selected]
    sampled_binary = binary[selected]
    unique_matrix, first, inverse = np.unique(
        sampled_matrix, axis=0, return_index=True, return_inverse=True
    )
    benign_by_vector = np.bincount(
        inverse, weights=(sampled_binary == 0), minlength=len(unique_matrix)
    )
    malicious_by_vector = np.bincount(
        inverse, weights=(sampled_binary == 1), minlength=len(unique_matrix)
    )
    ambiguous = (benign_by_vector > 0) & (malicious_by_vector > 0)
    ambiguous_rows = int(np.isin(inverse, np.flatnonzero(ambiguous)).sum())
    retained_positions = np.sort(first[~ambiguous])
    retained_indices = selected[retained_positions]
    retained_matrix = sampled_matrix[retained_positions]
    retained_binary = sampled_binary[retained_positions]
    if len(set(retained_binary.tolist())) != 2:
        raise ValueError(f"source {source_id} loses a class after ambiguity removal")
    manifest = {
        "source_id": source_id,
        "dataset": dataset.name,
        "dataset_fingerprint": dataset.fingerprint,
        "provenance_sha256": [item.sha256 for item in dataset.provenance],
        "input_rows": dataset.row_count,
        "input_groups": len(set(map(str, dataset.groups))),
        "sample_limit_per_binary_class": max_rows_per_class,
        "sampled_rows": len(selected),
        "sampled_indices_sha256": _indices_sha256(selected),
        "sampled_binary_distribution": {
            "benign": int(np.sum(sampled_binary == 0)),
            "malicious": int(np.sum(sampled_binary == 1)),
        },
        "unique_feature_vectors": len(unique_matrix),
        "duplicate_rows_removed": len(selected) - len(unique_matrix),
        "ambiguous_feature_vectors_removed": int(ambiguous.sum()),
        "ambiguous_rows_removed": ambiguous_rows,
        "retained_rows": len(retained_indices),
        "retained_indices_sha256": _indices_sha256(retained_indices),
        "retained_binary_distribution": {
            "benign": int(np.sum(retained_binary == 0)),
            "malicious": int(np.sum(retained_binary == 1)),
        },
    }
    return PreparedResearchSource(
        source_id=source_id,
        matrix=retained_matrix,
        binary_labels=retained_binary,
        family_labels=dataset.labels[retained_indices],
        groups=dataset.groups[retained_indices],
        timestamps=dataset.timestamps[retained_indices],
        manifest=manifest,
    )


def prepare_research_sources(
    datasets: dict[str, CanonicalDataset],
    *,
    max_rows_per_class: int,
    seed: int = RESEARCH_SEED,
) -> list[PreparedResearchSource]:
    if max_rows_per_class < 20:
        raise ValueError("max_rows_per_class must be at least 20")
    return [
        _prepare_source(
            source_id,
            dataset,
            max_rows_per_class=max_rows_per_class,
            seed=seed,
        )
        for source_id, dataset in datasets.items()
    ]


def _model(name: str, seed: int) -> tuple[Any, dict[str, Any]]:
    if name == "logistic_regression":
        config = {
            "class_weight": "balanced",
            "max_iter": 1500,
            "solver": "lbfgs",
        }
        return LogisticRegression(random_state=seed, **config), config
    if name == "calibrated_random_forest":
        forest_config = {
            "n_estimators": 160,
            "min_samples_leaf": 2,
            "class_weight": "balanced_subsample",
            "n_jobs": -1,
        }
        forest = RandomForestClassifier(random_state=seed, **forest_config)
        config = {
            "estimator": forest_config,
            "calibration": "sigmoid",
            "calibration_cv": "3-fold stratified development rows",
        }
        return (
            CalibratedClassifierCV(
                estimator=forest,
                method="sigmoid",
                cv=3,
                n_jobs=1,
            ),
            config,
        )
    if name == "hist_gradient_boosting":
        config = {
            "learning_rate": 0.08,
            "max_iter": 180,
            "max_leaf_nodes": 31,
            "l2_regularization": 1.0,
            "class_weight": "balanced",
        }
        return HistGradientBoostingClassifier(random_state=seed, **config), config
    if name == "compact_mlp":
        config = {
            "hidden_layer_sizes": [32, 16],
            "alpha": 0.0005,
            "batch_size": 256,
            "early_stopping": True,
            "max_iter": 250,
        }
        return MLPClassifier(random_state=seed, **config), config
    raise ValueError(f"unsupported supervised baseline: {name}")


def _expected_calibration_error(
    probability: np.ndarray, truth: np.ndarray, bins: int = 10
) -> float:
    confidence = np.maximum(probability, 1.0 - probability)
    correct = (probability >= 0.5) == truth.astype(bool)
    total = 0.0
    edges = np.linspace(0.0, 1.0, bins + 1)
    for lower, upper in pairwise(edges):
        selected = (confidence > lower) & (confidence <= upper)
        if selected.any():
            total += float(selected.mean()) * abs(
                float(correct[selected].mean()) - float(confidence[selected].mean())
            )
    return total


def _row_overlap(training: np.ndarray, testing: np.ndarray) -> int:
    train_rows = np.ascontiguousarray(training).view(
        np.dtype((np.void, training.dtype.itemsize * training.shape[1]))
    )
    test_rows = np.ascontiguousarray(testing).view(
        np.dtype((np.void, testing.dtype.itemsize * testing.shape[1]))
    )
    return int(np.intersect1d(train_rows, test_rows).size)


def _evaluate_model(
    name: str,
    x_train: np.ndarray,
    y_train: np.ndarray,
    x_test: np.ndarray,
    y_test: np.ndarray,
    *,
    seed: int,
) -> dict[str, Any]:
    preprocessor = RobustResearchPreprocessor(PORTABLE_NUMERICAL_CORE_FEATURE_NAMES)
    transformed_train = preprocessor.fit_transform(x_train)
    transformed_test = preprocessor.transform(x_test)
    estimator, config = _model(name, seed)
    process = psutil.Process()
    rss_before = process.memory_info().rss
    cpu_before = sum(process.cpu_times()[:2])
    fit_started = perf_counter()
    estimator.fit(transformed_train, y_train)
    fit_seconds = perf_counter() - fit_started
    fit_cpu_seconds = sum(process.cpu_times()[:2]) - cpu_before
    rss_after_fit = process.memory_info().rss

    inference_cpu_before = sum(process.cpu_times()[:2])
    inference_started = perf_counter()
    probabilities = np.asarray(estimator.predict_proba(transformed_test))[:, 1]
    inference_seconds = perf_counter() - inference_started
    inference_cpu_seconds = sum(process.cpu_times()[:2]) - inference_cpu_before
    predictions = (probabilities >= 0.5).astype(np.int8)
    single_latencies: list[float] = []
    for row in transformed_test[: min(100, len(transformed_test))]:
        started = perf_counter()
        estimator.predict_proba(row.reshape(1, -1))
        single_latencies.append((perf_counter() - started) * 1000.0)
    latency = np.asarray(single_latencies or [0.0])
    benign = y_test == 0
    malicious = y_test == 1
    precision, recall, thresholds = precision_recall_curve(y_test, probabilities)
    return {
        "model": name,
        "model_config": config,
        "decision_threshold": 0.5,
        "preprocessing": preprocessor.manifest(),
        "fit_seconds": fit_seconds,
        "fit_cpu_seconds": fit_cpu_seconds,
        "fit_rss_delta_bytes": rss_after_fit - rss_before,
        "inference_seconds": inference_seconds,
        "inference_cpu_seconds": inference_cpu_seconds,
        "throughput_rows_per_second": len(x_test) / max(inference_seconds, 1e-12),
        "single_row_latency_ms_p50": float(np.percentile(latency, 50)),
        "single_row_latency_ms_p95": float(np.percentile(latency, 95)),
        "accuracy": float(accuracy_score(y_test, predictions)),
        "balanced_accuracy": float(balanced_accuracy_score(y_test, predictions)),
        "macro_f1": float(f1_score(y_test, predictions, average="macro")),
        "weighted_f1": float(f1_score(y_test, predictions, average="weighted")),
        "pr_auc_malicious": float(average_precision_score(y_test, probabilities)),
        "roc_auc": float(roc_auc_score(y_test, probabilities)),
        "brier": float(brier_score_loss(y_test, probabilities)),
        "ece": _expected_calibration_error(probabilities, y_test),
        "benign_false_positive_rate": float(np.mean(predictions[benign] == 1)),
        "false_alerts_per_10000_benign": float(
            np.mean(predictions[benign] == 1) * 10_000
        ),
        "malicious_recall": float(np.mean(predictions[malicious] == 1)),
        "confusion_labels": ["benign", "malicious"],
        "confusion_matrix": confusion_matrix(y_test, predictions, labels=[0, 1]).tolist(),
        "classification_report": classification_report(
            y_test,
            predictions,
            labels=[0, 1],
            target_names=["benign", "malicious"],
            output_dict=True,
            zero_division=0,
        ),
        "precision_recall_curve": {
            "points": len(precision),
            "threshold_min": float(thresholds.min()) if len(thresholds) else None,
            "threshold_max": float(thresholds.max()) if len(thresholds) else None,
        },
    }


def run_cross_environment_supervised(
    datasets: dict[str, CanonicalDataset],
    *,
    models: tuple[str, ...] = DEFAULT_SUPERVISED_MODELS,
    max_rows_per_class: int = 10_000,
    seed: int = RESEARCH_SEED,
) -> dict[str, Any]:
    if len(datasets) < 3:
        raise ValueError("cross-environment baselines require at least three sources")
    if max_rows_per_class < 20:
        raise ValueError("max_rows_per_class must be at least 20")
    if not models or len(set(models)) != len(models):
        raise ValueError("models must be nonempty and unique")
    prepared = prepare_research_sources(
        datasets, max_rows_per_class=max_rows_per_class, seed=seed
    )
    rotations: list[dict[str, Any]] = []
    for held_out in prepared:
        training_sources = [source for source in prepared if source is not held_out]
        x_train = np.vstack([source.matrix for source in training_sources])
        y_train = np.concatenate([source.binary_labels for source in training_sources])
        x_test = held_out.matrix
        y_test = held_out.binary_labels
        if len(set(y_train.tolist())) != 2 or len(set(y_test.tolist())) != 2:
            raise ValueError("every cross-environment fold requires both binary classes")
        results = [
            _evaluate_model(
                name,
                x_train,
                y_train,
                x_test,
                y_test,
                seed=seed,
            )
            for name in models
        ]
        rotations.append(
            {
                "training_sources": [source.source_id for source in training_sources],
                "testing_source": held_out.source_id,
                "training_rows": len(x_train),
                "testing_rows": len(x_test),
                "training_binary_distribution": {
                    "benign": int(np.sum(y_train == 0)),
                    "malicious": int(np.sum(y_train == 1)),
                },
                "testing_binary_distribution": {
                    "benign": int(np.sum(y_test == 0)),
                    "malicious": int(np.sum(y_test == 1)),
                },
                "testing_attack_families": sorted(
                    set(map(str, held_out.family_labels[held_out.binary_labels == 1]))
                ),
                "exact_feature_row_overlap": _row_overlap(x_train, x_test),
                "models": results,
            }
        )
    summaries: dict[str, Any] = {}
    for model in models:
        results = [
            result
            for rotation in rotations
            for result in rotation["models"]
            if result["model"] == model
        ]
        summaries[model] = {
            "rotations": len(results),
            "macro_f1_mean": float(np.mean([item["macro_f1"] for item in results])),
            "macro_f1_min": float(np.min([item["macro_f1"] for item in results])),
            "benign_fpr_mean": float(
                np.mean([item["benign_false_positive_rate"] for item in results])
            ),
            "benign_fpr_max": float(
                np.max([item["benign_false_positive_rate"] for item in results])
            ),
            "malicious_recall_mean": float(
                np.mean([item["malicious_recall"] for item in results])
            ),
            "malicious_recall_min": float(
                np.min([item["malicious_recall"] for item in results])
            ),
            "ece_mean": float(np.mean([item["ece"] for item in results])),
            "inference_rows_per_second_mean": float(
                np.mean([item["throughput_rows_per_second"] for item in results])
            ),
        }
    return {
        "schema_version": "1.0.0",
        "experiment_type": "cross_environment_supervised_binary_baselines",
        "status": "development_evidence_only_no_candidate_selected",
        "seed": seed,
        "feature_schema": PORTABLE_SCHEMA_VERSION,
        "feature_view": "portable_numerical_core_after_origin_ablation",
        "feature_order": list(PORTABLE_NUMERICAL_CORE_FEATURE_NAMES),
        "target": "benign_vs_malicious",
        "sampling_policy": (
            "deterministic per-source binary-class cap; exact feature deduplication; "
            "conflicting-label feature vectors removed"
        ),
        "limitations": [
            "This is a supervised maliciousness baseline, not an unknown-behaviour result.",
            "Random-forest calibration uses stratified development rows because only two "
            "source environments remain in each training rotation.",
            "A fixed 0.5 threshold is reported; operational threshold selection is a later "
            "development-only experiment.",
        ],
        "sources": [source.manifest for source in prepared],
        "models": list(models),
        "rotations": rotations,
        "summary": summaries,
    }
