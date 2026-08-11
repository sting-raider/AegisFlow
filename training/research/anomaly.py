from __future__ import annotations

from time import perf_counter
from typing import Any

import numpy as np
import psutil
import torch
from sklearn.covariance import EllipticEnvelope
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM

from packages.detection.autoencoder import DenoisingAutoencoder, reconstruction_errors
from packages.features.research import (
    PORTABLE_NUMERICAL_CORE_FEATURE_NAMES,
    PORTABLE_SCHEMA_VERSION,
)
from training.data.models import CanonicalDataset
from training.features import RobustResearchPreprocessor
from training.research.baselines import (
    RESEARCH_SEED,
    PreparedResearchSource,
    prepare_research_sources,
)

DEFAULT_ANOMALY_MODELS = (
    "isolation_forest",
    "robust_covariance",
    "local_outlier_factor",
    "one_class_svm",
    "denoising_autoencoder",
)
_FPR_BUDGETS = (0.005, 0.01, 0.03, 0.05)


def _fit_cap(matrix: np.ndarray, *, limit: int, seed: int) -> np.ndarray:
    if len(matrix) <= limit:
        return matrix
    selected = np.sort(
        np.random.default_rng(seed).choice(len(matrix), size=limit, replace=False)
    )
    return matrix[selected]


def _train_autoencoder(
    values: np.ndarray, *, seed: int, epochs: int = 100
) -> DenoisingAutoencoder:
    torch.manual_seed(seed)
    torch.set_num_threads(1)
    input_dim = values.shape[1]
    model = DenoisingAutoencoder(
        input_dim,
        hidden_dim=max(8, min(16, input_dim * 2)),
        bottleneck_dim=max(3, min(6, input_dim // 2 + 1)),
    )
    optimizer = torch.optim.Adam(model.parameters(), lr=0.004, weight_decay=1e-5)
    clean = torch.as_tensor(values, dtype=torch.float32)
    generator = torch.Generator(device="cpu").manual_seed(seed)
    model.train()
    for _ in range(epochs):
        noisy = clean + torch.randn(clean.shape, generator=generator) * 0.06
        optimizer.zero_grad(set_to_none=True)
        loss = torch.mean((model(noisy) - clean) ** 2)
        loss.backward()  # type: ignore[no-untyped-call]
        optimizer.step()
    model.eval()
    return model


def fit_anomaly_model(
    name: str, matrix: np.ndarray, *, seed: int
) -> tuple[Any, dict[str, Any], int]:
    if name == "isolation_forest":
        config = {"n_estimators": 200, "contamination": "auto", "n_jobs": -1}
        estimator = IsolationForest(random_state=seed, **config).fit(matrix)
        return estimator, config, len(matrix)
    if name == "robust_covariance":
        fit = _fit_cap(matrix, limit=5_000, seed=seed)
        covariance_config: dict[str, Any] = {
            "support_fraction": 0.9,
            "contamination": 0.01,
        }
        config = {**covariance_config, "fit_cap": 5_000}
        estimator = EllipticEnvelope(random_state=seed, **covariance_config).fit(fit)
        return estimator, config, len(fit)
    if name == "local_outlier_factor":
        fit = _fit_cap(matrix, limit=10_000, seed=seed)
        lof_config: dict[str, Any] = {
            "n_neighbors": 35,
            "novelty": True,
            "contamination": 0.01,
            "n_jobs": -1,
        }
        config = {**lof_config, "fit_cap": 10_000}
        estimator = LocalOutlierFactor(**lof_config).fit(fit)
        return estimator, config, len(fit)
    if name == "one_class_svm":
        fit = _fit_cap(matrix, limit=5_000, seed=seed)
        svm_config: dict[str, Any] = {
            "kernel": "rbf",
            "gamma": "scale",
            "nu": 0.01,
        }
        config = {**svm_config, "fit_cap": 5_000}
        estimator = OneClassSVM(**svm_config).fit(fit)
        return estimator, config, len(fit)
    if name == "denoising_autoencoder":
        fit = _fit_cap(matrix, limit=10_000, seed=seed)
        config = {
            "epochs": 100,
            "noise_std": 0.06,
            "fit_cap": 10_000,
            "optimizer": "Adam(lr=0.004, weight_decay=1e-5)",
        }
        return _train_autoencoder(fit, seed=seed), config, len(fit)
    raise ValueError(f"unsupported anomaly baseline: {name}")


def anomaly_scores(name: str, estimator: Any, matrix: np.ndarray) -> np.ndarray:
    if name == "denoising_autoencoder":
        scores = reconstruction_errors(estimator, matrix)
    else:
        scores = -np.asarray(estimator.decision_function(matrix), dtype=np.float64)
    scores = np.asarray(scores, dtype=np.float64).reshape(-1)
    if len(scores) != len(matrix) or not np.isfinite(scores).all():
        raise ValueError(f"{name} produced invalid anomaly scores")
    return scores


def calibration_threshold(scores: np.ndarray, false_positive_budget: float) -> float:
    return float(np.quantile(scores, 1.0 - false_positive_budget, method="higher"))


def _percentiles(values: np.ndarray) -> dict[str, float]:
    return {
        f"p{percentile:02d}": float(np.percentile(values, percentile))
        for percentile in (50, 90, 95, 99)
    }


def _family_metrics(
    families: np.ndarray,
    binary: np.ndarray,
    direct: np.ndarray,
    review: np.ndarray,
) -> dict[str, dict[str, float | int]]:
    result: dict[str, dict[str, float | int]] = {}
    for family in sorted(set(map(str, families[binary == 1]))):
        selected = (families == family) & (binary == 1)
        result[family] = {
            "rows": int(selected.sum()),
            "direct_suspicious_unknown_recall": float(np.mean(direct[selected])),
            "detection_or_review_recall": float(np.mean(review[selected])),
        }
    return result


def _evaluate_anomaly_model(
    name: str,
    fit_source: PreparedResearchSource,
    calibration_source: PreparedResearchSource,
    testing_source: PreparedResearchSource,
    *,
    seed: int,
) -> dict[str, Any]:
    fit_benign = fit_source.matrix[fit_source.binary_labels == 0]
    calibration_benign = calibration_source.matrix[
        calibration_source.binary_labels == 0
    ]
    preprocessor = RobustResearchPreprocessor(PORTABLE_NUMERICAL_CORE_FEATURE_NAMES)
    transformed_fit = preprocessor.fit_transform(fit_benign)
    transformed_calibration = preprocessor.transform(calibration_benign)
    transformed_test = preprocessor.transform(testing_source.matrix)
    process = psutil.Process()
    rss_before = process.memory_info().rss
    cpu_before = sum(process.cpu_times()[:2])
    fit_started = perf_counter()
    estimator, config, model_fit_rows = fit_anomaly_model(
        name, transformed_fit, seed=seed
    )
    fit_seconds = perf_counter() - fit_started
    fit_cpu_seconds = sum(process.cpu_times()[:2]) - cpu_before
    rss_after_fit = process.memory_info().rss
    calibration_scores = anomaly_scores(name, estimator, transformed_calibration)

    inference_cpu_before = sum(process.cpu_times()[:2])
    inference_started = perf_counter()
    test_scores = anomaly_scores(name, estimator, transformed_test)
    inference_seconds = perf_counter() - inference_started
    inference_cpu_seconds = sum(process.cpu_times()[:2]) - inference_cpu_before
    y_test = testing_source.binary_labels
    benign = y_test == 0
    malicious = y_test == 1
    direct_threshold = calibration_threshold(calibration_scores, 0.01)
    review_threshold = calibration_threshold(calibration_scores, 0.05)
    direct = test_scores > direct_threshold
    review = test_scores > review_threshold
    curve: list[dict[str, float]] = []
    for budget in _FPR_BUDGETS:
        threshold = calibration_threshold(calibration_scores, budget)
        calibration_flags = calibration_scores > threshold
        test_flags = test_scores > threshold
        curve.append(
            {
                "calibration_benign_fpr_budget": budget,
                "threshold": threshold,
                "calibration_observed_fpr": float(np.mean(calibration_flags)),
                "test_benign_fpr": float(np.mean(test_flags[benign])),
                "test_malicious_recall": float(np.mean(test_flags[malicious])),
                "test_alerts_per_10000_benign": float(
                    np.mean(test_flags[benign]) * 10_000
                ),
            }
        )
    single_latencies: list[float] = []
    for row in transformed_test[: min(100, len(transformed_test))]:
        started = perf_counter()
        anomaly_scores(name, estimator, row.reshape(1, -1))
        single_latencies.append((perf_counter() - started) * 1000.0)
    latency = np.asarray(single_latencies or [0.0])
    return {
        "model": name,
        "status": "complete",
        "model_config": config,
        "preprocessing": preprocessor.manifest(),
        "fit_source": fit_source.source_id,
        "calibration_source": calibration_source.source_id,
        "testing_source": testing_source.source_id,
        "fit_benign_rows": len(fit_benign),
        "model_fit_benign_rows": model_fit_rows,
        "calibration_benign_rows": len(calibration_benign),
        "testing_rows": len(y_test),
        "testing_binary_distribution": {
            "benign": int(benign.sum()),
            "malicious": int(malicious.sum()),
        },
        "direct_threshold": direct_threshold,
        "review_threshold": review_threshold,
        "calibration_direct_fpr": float(
            np.mean(calibration_scores > direct_threshold)
        ),
        "calibration_review_rate": float(
            np.mean(calibration_scores > review_threshold)
        ),
        "test_benign_false_positive_rate": float(np.mean(direct[benign])),
        "test_benign_review_or_alert_rate": float(np.mean(review[benign])),
        "false_alerts_per_10000_benign": float(np.mean(direct[benign]) * 10_000),
        "direct_suspicious_unknown_recall": float(np.mean(direct[malicious])),
        "detection_or_review_recall": float(np.mean(review[malicious])),
        "pr_auc_malicious": float(average_precision_score(y_test, test_scores)),
        "roc_auc": float(roc_auc_score(y_test, test_scores)),
        "score_percentiles": {
            "calibration_benign": _percentiles(calibration_scores),
            "testing_benign": _percentiles(test_scores[benign]),
            "testing_malicious": _percentiles(test_scores[malicious]),
        },
        "per_family": _family_metrics(
            testing_source.family_labels, y_test, direct, review
        ),
        "operating_curve": curve,
        "fit_seconds": fit_seconds,
        "fit_cpu_seconds": fit_cpu_seconds,
        "fit_rss_delta_bytes": rss_after_fit - rss_before,
        "inference_seconds": inference_seconds,
        "inference_cpu_seconds": inference_cpu_seconds,
        "throughput_rows_per_second": len(y_test) / max(inference_seconds, 1e-12),
        "single_row_latency_ms_p50": float(np.percentile(latency, 50)),
        "single_row_latency_ms_p95": float(np.percentile(latency, 95)),
        "false_alerts_per_hour": None,
        "false_alerts_per_hour_reason": (
            "not reported because deterministic class sampling changes replay density"
        ),
    }


def run_cross_environment_anomaly_baselines(
    datasets: dict[str, CanonicalDataset],
    *,
    models: tuple[str, ...] = DEFAULT_ANOMALY_MODELS,
    max_rows_per_class: int = 10_000,
    seed: int = RESEARCH_SEED,
) -> dict[str, Any]:
    if len(datasets) != 3:
        raise ValueError(
            "three-way fit/calibration/test anomaly baselines require exactly three sources"
        )
    if not models or len(set(models)) != len(models):
        raise ValueError("models must be nonempty and unique")
    prepared = prepare_research_sources(
        datasets, max_rows_per_class=max_rows_per_class, seed=seed
    )
    runs: list[dict[str, Any]] = []
    for testing_source in prepared:
        development = [source for source in prepared if source is not testing_source]
        for fit_source, calibration_source in (
            (development[0], development[1]),
            (development[1], development[0]),
        ):
            for model in models:
                try:
                    result = _evaluate_anomaly_model(
                        model,
                        fit_source,
                        calibration_source,
                        testing_source,
                        seed=seed,
                    )
                except Exception as error:  # visible experiment failure, never benign data
                    result = {
                        "model": model,
                        "status": "failed",
                        "fit_source": fit_source.source_id,
                        "calibration_source": calibration_source.source_id,
                        "testing_source": testing_source.source_id,
                        "error_type": type(error).__name__,
                        "error": str(error)[:500],
                    }
                runs.append(result)
    summaries: dict[str, Any] = {}
    for model in models:
        selected = [item for item in runs if item["model"] == model]
        complete = [item for item in selected if item["status"] == "complete"]
        summary: dict[str, Any] = {
            "runs": len(selected),
            "completed_runs": len(complete),
            "failed_runs": len(selected) - len(complete),
        }
        if complete:
            summary.update(
                {
                    "direct_unknown_recall_mean": float(
                        np.mean(
                            [item["direct_suspicious_unknown_recall"] for item in complete]
                        )
                    ),
                    "direct_unknown_recall_min": float(
                        np.min(
                            [item["direct_suspicious_unknown_recall"] for item in complete]
                        )
                    ),
                    "detection_or_review_mean": float(
                        np.mean([item["detection_or_review_recall"] for item in complete])
                    ),
                    "detection_or_review_min": float(
                        np.min([item["detection_or_review_recall"] for item in complete])
                    ),
                    "benign_fpr_mean": float(
                        np.mean([item["test_benign_false_positive_rate"] for item in complete])
                    ),
                    "benign_fpr_max": float(
                        np.max([item["test_benign_false_positive_rate"] for item in complete])
                    ),
                    "benign_review_or_alert_rate_mean": float(
                        np.mean(
                            [item["test_benign_review_or_alert_rate"] for item in complete]
                        )
                    ),
                }
            )
        summaries[model] = summary
    return {
        "schema_version": "1.0.0",
        "experiment_type": "three_way_cross_environment_benign_only_anomaly_baselines",
        "status": "development_evidence_only_no_candidate_selected",
        "seed": seed,
        "feature_schema": PORTABLE_SCHEMA_VERSION,
        "feature_view": "portable_numerical_core_after_origin_ablation",
        "feature_order": list(PORTABLE_NUMERICAL_CORE_FEATURE_NAMES),
        "fit_policy": "benign only from one environment",
        "calibration_policy": (
            "benign only from a second environment; direct threshold at 1% calibration "
            "FPR and review threshold at 5%"
        ),
        "test_policy": (
            "third environment held out completely; every malicious family is absent "
            "from anomaly fit and calibration"
        ),
        "limitations": [
            "Class sampling and exact-vector deduplication prevent representative "
            "false-alerts-per-hour estimates.",
            "Anomaly results are not classifier probabilities; ECE and Brier are not applicable.",
            "This experiment does not include temporal Schema B or signature evidence.",
        ],
        "sources": [source.manifest for source in prepared],
        "models": list(models),
        "runs": runs,
        "summary": summaries,
    }
