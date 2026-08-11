from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter
from typing import Any

import numpy as np
import psutil
from sklearn.metrics import average_precision_score, brier_score_loss, confusion_matrix

from packages.features.research import (
    PORTABLE_NUMERICAL_CORE_FEATURE_NAMES,
    RUNTIME_ENRICHED_FEATURE_NAMES,
    TEMPORAL_FEATURE_NAMES,
    TEMPORAL_SCHEMA_VERSION,
)
from training.data.models import CanonicalDataset
from training.features import RobustResearchPreprocessor
from training.research.anomaly import (
    anomaly_scores,
    calibration_threshold,
    fit_anomaly_model,
)
from training.research.baselines import (
    RESEARCH_SEED,
    prepare_research_sources,
    supervised_model,
)

DEFAULT_HYBRID_SUPERVISED_MODEL = "compact_mlp"
DEFAULT_HYBRID_ANOMALY_MODEL = "isolation_forest"
_DIRECT_FPR_BUDGET = 0.01
_REVIEW_FPR_BUDGET = 0.05
_CURVE_BUDGETS = (0.005, 0.01, 0.03, 0.05)
_PORT_CONTEXT_FEATURES = {
    "unique_destination_ports_10s_log1p",
    "unique_destination_ports_60s_log1p",
    "service_port_rarity_60s",
}


@dataclass(frozen=True)
class _SignalScores:
    name: str
    calibration: np.ndarray
    testing: np.ndarray
    fit_manifest: dict[str, Any]


def _indices(names: tuple[str, ...]) -> np.ndarray:
    return np.asarray([RUNTIME_ENRICHED_FEATURE_NAMES.index(name) for name in names])


def _expected_calibration_error(
    probabilities: np.ndarray, truth: np.ndarray, bins: int = 10
) -> float:
    total = 0.0
    edges = np.linspace(0.0, 1.0, bins + 1)
    for index in range(bins):
        lower = edges[index]
        upper = edges[index + 1]
        selected = (probabilities > lower) & (probabilities <= upper)
        if selected.any():
            total += float(selected.mean()) * abs(
                float(truth[selected].mean()) - float(probabilities[selected].mean())
            )
    return total


def _source_manifest(source_id: str, dataset: CanonicalDataset) -> dict[str, Any]:
    return {
        "source_id": source_id,
        "dataset": dataset.name,
        "dataset_fingerprint": dataset.fingerprint,
        "provenance_sha256": [item.sha256 for item in dataset.provenance],
        "input_rows": dataset.row_count,
        "input_groups": len(set(map(str, dataset.groups))),
        "binary_distribution": {
            "benign": int(np.sum(dataset.labels == "benign")),
            "malicious": int(np.sum(dataset.labels != "benign")),
        },
    }


def _fit_classifier(
    prepared: list[Any],
    held_family: str,
    temporal_matrix: np.ndarray,
    *,
    model_name: str,
    seed: int,
) -> tuple[np.ndarray, dict[str, Any]]:
    matrices: list[np.ndarray] = []
    labels: list[np.ndarray] = []
    training_families: set[str] = set()
    excluded_rows = 0
    for source in prepared:
        selected = source.family_labels != held_family
        excluded_rows += int((~selected).sum())
        matrices.append(source.matrix[selected])
        labels.append(source.binary_labels[selected])
        training_families.update(
            map(str, source.family_labels[selected & (source.binary_labels == 1)])
        )
    training_matrix = np.vstack(matrices)
    training_labels = np.concatenate(labels)
    if len(set(training_labels.tolist())) != 2:
        raise ValueError(f"held family {held_family} leaves classifier training with one class")
    if held_family in training_families:
        raise ValueError(f"held family leaked into classifier training: {held_family}")
    preprocessor = RobustResearchPreprocessor(PORTABLE_NUMERICAL_CORE_FEATURE_NAMES)
    transformed_training = preprocessor.fit_transform(training_matrix)
    core_matrix = temporal_matrix[:, _indices(PORTABLE_NUMERICAL_CORE_FEATURE_NAMES)]
    transformed_temporal = preprocessor.transform(core_matrix)
    estimator, config = supervised_model(model_name, seed)
    process = psutil.Process()
    rss_before = process.memory_info().rss
    cpu_before = sum(process.cpu_times()[:2])
    started = perf_counter()
    estimator.fit(transformed_training, training_labels)
    fit_seconds = perf_counter() - started
    fit_cpu_seconds = sum(process.cpu_times()[:2]) - cpu_before
    rss_after = process.memory_info().rss
    inference_started = perf_counter()
    probabilities = np.asarray(estimator.predict_proba(transformed_temporal))[:, 1]
    inference_seconds = perf_counter() - inference_started
    if not np.isfinite(probabilities).all():
        raise ValueError("supervised model produced non-finite probabilities")
    return probabilities, {
        "model": model_name,
        "model_config": config,
        "held_family": held_family,
        "held_family_rows_excluded": excluded_rows,
        "training_attack_families": sorted(training_families),
        "training_rows": len(training_labels),
        "training_binary_distribution": {
            "benign": int(np.sum(training_labels == 0)),
            "malicious": int(np.sum(training_labels == 1)),
        },
        "preprocessing": preprocessor.manifest(),
        "fit_seconds": fit_seconds,
        "fit_cpu_seconds": fit_cpu_seconds,
        "fit_rss_delta_bytes": rss_after - rss_before,
        "inference_seconds_all_temporal_rows": inference_seconds,
        "throughput_rows_per_second": len(temporal_matrix)
        / max(inference_seconds, 1e-12),
    }


def _fit_anomaly_signal(
    name: str,
    feature_names: tuple[str, ...],
    matrix: np.ndarray,
    fit_indices: np.ndarray,
    calibration_indices: np.ndarray,
    *,
    model_name: str,
    seed: int,
) -> _SignalScores:
    selected_matrix = matrix[:, _indices(feature_names)]
    preprocessor = RobustResearchPreprocessor(feature_names)
    transformed_fit = preprocessor.fit_transform(selected_matrix[fit_indices])
    transformed_calibration = preprocessor.transform(selected_matrix[calibration_indices])
    transformed_all = preprocessor.transform(selected_matrix)
    process = psutil.Process()
    rss_before = process.memory_info().rss
    cpu_before = sum(process.cpu_times()[:2])
    started = perf_counter()
    estimator, config, model_fit_rows = fit_anomaly_model(
        model_name, transformed_fit, seed=seed
    )
    fit_seconds = perf_counter() - started
    fit_cpu_seconds = sum(process.cpu_times()[:2]) - cpu_before
    rss_after = process.memory_info().rss
    calibration = anomaly_scores(model_name, estimator, transformed_calibration)
    inference_started = perf_counter()
    testing = anomaly_scores(model_name, estimator, transformed_all)
    inference_seconds = perf_counter() - inference_started
    return _SignalScores(
        name=name,
        calibration=calibration,
        testing=testing,
        fit_manifest={
            "signal": name,
            "model": model_name,
            "model_config": config,
            "feature_order": list(feature_names),
            "fit_benign_rows": len(fit_indices),
            "model_fit_benign_rows": model_fit_rows,
            "calibration_benign_rows": len(calibration_indices),
            "preprocessing": preprocessor.manifest(),
            "fit_seconds": fit_seconds,
            "fit_cpu_seconds": fit_cpu_seconds,
            "fit_rss_delta_bytes": rss_after - rss_before,
            "inference_seconds_all_temporal_rows": inference_seconds,
            "throughput_rows_per_second": len(matrix) / max(inference_seconds, 1e-12),
        },
    )


def _thresholds(
    signals: tuple[_SignalScores, ...], total_budget: float
) -> dict[str, float]:
    per_signal_budget = total_budget / len(signals)
    return {
        signal.name: calibration_threshold(signal.calibration, per_signal_budget)
        for signal in signals
    }


def _flags(
    signals: tuple[_SignalScores, ...],
    thresholds: dict[str, float],
    indices: np.ndarray,
) -> np.ndarray:
    return np.asarray(
        np.logical_or.reduce(
            [signal.testing[indices] > thresholds[signal.name] for signal in signals]
        ),
        dtype=bool,
    )


def _calibration_flags(
    signals: tuple[_SignalScores, ...], thresholds: dict[str, float]
) -> np.ndarray:
    return np.asarray(
        np.logical_or.reduce(
            [signal.calibration > thresholds[signal.name] for signal in signals]
        ),
        dtype=bool,
    )


def _evaluate_ablation(
    name: str,
    signals: tuple[_SignalScores, ...],
    unknown_signal_names: frozenset[str],
    test_indices: np.ndarray,
    labels: np.ndarray,
) -> dict[str, Any]:
    direct_thresholds = _thresholds(signals, _DIRECT_FPR_BUDGET)
    review_thresholds = _thresholds(signals, _REVIEW_FPR_BUDGET)
    direct = _flags(signals, direct_thresholds, test_indices)
    review = _flags(signals, review_thresholds, test_indices) | direct
    unknown_signals = tuple(
        signal for signal in signals if signal.name in unknown_signal_names
    )
    unknown = (
        _flags(
            unknown_signals,
            {key: direct_thresholds[key] for key in unknown_signal_names},
            test_indices,
        )
        if unknown_signals
        else np.zeros(len(test_indices), dtype=bool)
    )
    supervised = next((signal for signal in signals if signal.name == "supervised"), None)
    supervised_direct = (
        supervised.testing[test_indices] > direct_thresholds["supervised"]
        if supervised is not None
        else np.zeros(len(test_indices), dtype=bool)
    )
    truth = labels[test_indices] != "benign"
    benign = ~truth
    malicious = truth
    suspicious_unknown = unknown
    known_attack_evidence = supervised_direct & ~suspicious_unknown
    needs_review = review & ~direct
    benign_verdict = ~review
    return {
        "ablation": name,
        "signals": [signal.name for signal in signals],
        "direct_thresholds": direct_thresholds,
        "review_thresholds": review_thresholds,
        "calibration_direct_fpr": float(
            np.mean(_calibration_flags(signals, direct_thresholds))
        ),
        "calibration_review_rate": float(
            np.mean(_calibration_flags(signals, review_thresholds))
        ),
        "test_benign_fpr": float(np.mean(direct[benign])),
        "test_benign_review_or_alert_rate": float(np.mean(review[benign])),
        "false_alerts_per_10000_benign": float(np.mean(direct[benign]) * 10_000),
        "direct_detection_recall": float(np.mean(direct[malicious])),
        "direct_suspicious_unknown_recall": float(
            np.mean(suspicious_unknown[malicious])
        ),
        "detection_or_review_recall": float(np.mean(review[malicious])),
        "confusion_labels": ["benign", "malicious"],
        "direct_confusion_matrix": confusion_matrix(
            truth.astype(np.int8), direct.astype(np.int8), labels=[0, 1]
        ).tolist(),
        "verdict_distribution": {
            "benign": int(benign_verdict.sum()),
            "needs_review": int(needs_review.sum()),
            "known_attack_evidence": int(known_attack_evidence.sum()),
            "suspicious_unknown": int(suspicious_unknown.sum()),
        },
    }


def _operating_curve(
    signals: tuple[_SignalScores, ...],
    test_indices: np.ndarray,
    labels: np.ndarray,
) -> list[dict[str, float]]:
    truth = labels[test_indices] != "benign"
    benign = ~truth
    malicious = truth
    result: list[dict[str, float]] = []
    for budget in _CURVE_BUDGETS:
        thresholds = _thresholds(signals, budget)
        flags = _flags(signals, thresholds, test_indices)
        result.append(
            {
                "calibration_benign_fpr_budget": budget,
                "calibration_observed_fpr": float(
                    np.mean(_calibration_flags(signals, thresholds))
                ),
                "test_benign_fpr": float(np.mean(flags[benign])),
                "test_malicious_recall": float(np.mean(flags[malicious])),
                "test_alerts_per_10000_benign": float(
                    np.mean(flags[benign]) * 10_000
                ),
            }
        )
    return result


def run_held_family_hybrid_temporal(
    supervised_datasets: dict[str, CanonicalDataset],
    temporal_source_id: str,
    temporal_dataset: CanonicalDataset,
    *,
    supervised_model_name: str = DEFAULT_HYBRID_SUPERVISED_MODEL,
    anomaly_model_name: str = DEFAULT_HYBRID_ANOMALY_MODEL,
    max_rows_per_class: int = 10_000,
    minimum_family_rows: int = 20,
    seed: int = RESEARCH_SEED,
) -> dict[str, Any]:
    if len(supervised_datasets) < 2:
        raise ValueError("hybrid held-family evaluation requires two supervised sources")
    if temporal_dataset.runtime_enriched_features is None:
        raise ValueError("hybrid held-family evaluation requires research Schema B")
    if minimum_family_rows < 2:
        raise ValueError("minimum_family_rows must be at least two")
    matrix = temporal_dataset.runtime_enriched_features
    labels = temporal_dataset.labels
    groups = np.asarray(temporal_dataset.groups, dtype=str)
    benign_groups = sorted(
        group
        for group in set(groups.tolist())
        if np.all(labels[groups == group] == "benign")
    )
    if len(benign_groups) < 2:
        raise ValueError("Schema B source requires two all-benign capture groups")
    calibration_groups = benign_groups[:2]
    family_counts = {
        family: int(np.sum(labels == family))
        for family in sorted(set(map(str, labels)))
        if family != "benign"
    }
    held_families = [
        family for family, count in family_counts.items() if count >= minimum_family_rows
    ]
    if len(held_families) < 2:
        raise ValueError("held-family evaluation requires at least two eligible families")
    prepared = prepare_research_sources(
        supervised_datasets,
        max_rows_per_class=max_rows_per_class,
        seed=seed,
    )
    core_names = PORTABLE_NUMERICAL_CORE_FEATURE_NAMES
    temporal_names = tuple(TEMPORAL_FEATURE_NAMES)
    full_names = core_names + temporal_names
    no_port_names = core_names + tuple(
        name for name in temporal_names if name not in _PORT_CONTEXT_FEATURES
    )
    orientations: list[dict[str, Any]] = []
    anomaly_cache: dict[tuple[str, str], dict[str, _SignalScores]] = {}
    for fit_group, calibration_group in (
        (calibration_groups[0], calibration_groups[1]),
        (calibration_groups[1], calibration_groups[0]),
    ):
        fit_indices = np.flatnonzero((groups == fit_group) & (labels == "benign"))
        calibration_indices = np.flatnonzero(
            (groups == calibration_group) & (labels == "benign")
        )
        signal_map = {
            "anomaly_core": _fit_anomaly_signal(
                "anomaly_core",
                core_names,
                matrix,
                fit_indices,
                calibration_indices,
                model_name=anomaly_model_name,
                seed=seed,
            ),
            "context_only": _fit_anomaly_signal(
                "context_only",
                temporal_names,
                matrix,
                fit_indices,
                calibration_indices,
                model_name=anomaly_model_name,
                seed=seed,
            ),
            "anomaly_temporal": _fit_anomaly_signal(
                "anomaly_temporal",
                full_names,
                matrix,
                fit_indices,
                calibration_indices,
                model_name=anomaly_model_name,
                seed=seed,
            ),
            "anomaly_no_port_context": _fit_anomaly_signal(
                "anomaly_no_port_context",
                no_port_names,
                matrix,
                fit_indices,
                calibration_indices,
                model_name=anomaly_model_name,
                seed=seed,
            ),
        }
        anomaly_cache[(fit_group, calibration_group)] = signal_map
        orientations.append(
            {
                "fit_benign_group": fit_group,
                "calibration_benign_group": calibration_group,
                "fit_benign_rows": len(fit_indices),
                "calibration_benign_rows": len(calibration_indices),
                "anomaly_signals": [
                    signal.fit_manifest for signal in signal_map.values()
                ],
            }
        )

    runs: list[dict[str, Any]] = []
    classifier_fits: list[dict[str, Any]] = []
    for family in held_families:
        probabilities, classifier_manifest = _fit_classifier(
            prepared,
            family,
            matrix,
            model_name=supervised_model_name,
            seed=seed,
        )
        classifier_fits.append(classifier_manifest)
        family_groups = sorted(set(groups[labels == family].tolist()))
        if set(family_groups) & set(calibration_groups):
            raise ValueError(f"held family appears in benign fit/calibration groups: {family}")
        test_mask = (labels == family) | (
            (labels == "benign") & np.isin(groups, family_groups)
        )
        test_indices = np.flatnonzero(test_mask)
        if not np.any(labels[test_indices] == "benign"):
            raise ValueError(f"held family {family} test has no same-capture benign rows")
        if not np.any(labels[test_indices] == family):
            raise ValueError(f"held family {family} test has no malicious rows")
        for fit_group, calibration_group in (
            (calibration_groups[0], calibration_groups[1]),
            (calibration_groups[1], calibration_groups[0]),
        ):
            calibration_indices = np.flatnonzero(
                (groups == calibration_group) & (labels == "benign")
            )
            supervised_signal = _SignalScores(
                name="supervised",
                calibration=probabilities[calibration_indices],
                testing=probabilities,
                fit_manifest=classifier_manifest,
            )
            signals = anomaly_cache[(fit_group, calibration_group)]
            ablation_definitions = {
                "supervised_only": ((supervised_signal,), frozenset()),
                "anomaly_core_only": (
                    (signals["anomaly_core"],),
                    frozenset({"anomaly_core"}),
                ),
                "context_only": (
                    (signals["context_only"],),
                    frozenset({"context_only"}),
                ),
                "supervised_plus_anomaly": (
                    (supervised_signal, signals["anomaly_core"]),
                    frozenset({"anomaly_core"}),
                ),
                "supervised_plus_context": (
                    (supervised_signal, signals["context_only"]),
                    frozenset({"context_only"}),
                ),
                "anomaly_plus_context": (
                    (signals["anomaly_temporal"],),
                    frozenset({"anomaly_temporal"}),
                ),
                "full_hybrid": (
                    (supervised_signal, signals["anomaly_temporal"]),
                    frozenset({"anomaly_temporal"}),
                ),
                "without_temporal": (
                    (supervised_signal, signals["anomaly_core"]),
                    frozenset({"anomaly_core"}),
                ),
                "without_destination_port_information": (
                    (supervised_signal, signals["anomaly_no_port_context"]),
                    frozenset({"anomaly_no_port_context"}),
                ),
            }
            ablations = [
                _evaluate_ablation(
                    name,
                    definition[0],
                    definition[1],
                    test_indices,
                    labels,
                )
                for name, definition in ablation_definitions.items()
            ]
            truth = (labels[test_indices] != "benign").astype(np.int8)
            full_signals = (
                supervised_signal,
                signals["anomaly_temporal"],
            )
            runs.append(
                {
                    "held_family": family,
                    "held_family_rows": int(np.sum(labels[test_indices] == family)),
                    "test_groups": family_groups,
                    "test_rows": len(test_indices),
                    "test_benign_rows": int(np.sum(labels[test_indices] == "benign")),
                    "fit_benign_group": fit_group,
                    "calibration_benign_group": calibration_group,
                    "classifier_brier": float(
                        brier_score_loss(truth, probabilities[test_indices])
                    ),
                    "classifier_ece": _expected_calibration_error(
                        probabilities[test_indices], truth
                    ),
                    "classifier_pr_auc": float(
                        average_precision_score(truth, probabilities[test_indices])
                    ),
                    "ablations": ablations,
                    "full_hybrid_operating_curve": _operating_curve(
                        full_signals, test_indices, labels
                    ),
                    "signature_ablation": {
                        "status": "not_evaluable",
                        "reason": (
                            "IoT-23 flow logs do not include replay-correlated Suricata "
                            "signature evidence; no signature result is fabricated"
                        ),
                    },
                }
            )

    summary: dict[str, Any] = {}
    ablation_names = [item["ablation"] for item in runs[0]["ablations"]]
    for name in ablation_names:
        selected = [
            ablation
            for run in runs
            for ablation in run["ablations"]
            if ablation["ablation"] == name
        ]
        summary[name] = {
            "runs": len(selected),
            "direct_detection_recall_mean": float(
                np.mean([item["direct_detection_recall"] for item in selected])
            ),
            "direct_detection_recall_min": float(
                np.min([item["direct_detection_recall"] for item in selected])
            ),
            "direct_suspicious_unknown_recall_mean": float(
                np.mean(
                    [item["direct_suspicious_unknown_recall"] for item in selected]
                )
            ),
            "direct_suspicious_unknown_recall_min": float(
                np.min(
                    [item["direct_suspicious_unknown_recall"] for item in selected]
                )
            ),
            "detection_or_review_recall_mean": float(
                np.mean([item["detection_or_review_recall"] for item in selected])
            ),
            "detection_or_review_recall_min": float(
                np.min([item["detection_or_review_recall"] for item in selected])
            ),
            "benign_fpr_mean": float(
                np.mean([item["test_benign_fpr"] for item in selected])
            ),
            "benign_fpr_max": float(
                np.max([item["test_benign_fpr"] for item in selected])
            ),
        }
    return {
        "schema_version": "1.0.0",
        "experiment_type": "cross_environment_held_family_hybrid_temporal_ablation",
        "status": "development_evidence_only_no_candidate_selected",
        "seed": seed,
        "feature_schema": TEMPORAL_SCHEMA_VERSION,
        "feature_view": "portable_numerical_core_plus_bounded_temporal_context",
        "feature_order": list(full_names),
        "supervised_model": supervised_model_name,
        "anomaly_model": anomaly_model_name,
        "fit_policy": (
            "supervised fit on non-temporal development environments after removing the "
            "held family; anomaly fit on one all-benign IoT capture"
        ),
        "calibration_policy": (
            "thresholds use a second all-benign IoT capture; multi-signal budgets are "
            "split equally so combined direct/review calibration budgets remain 1%/5%"
        ),
        "test_policy": (
            "all rows of each eligible IoT family plus benign rows from the same capture "
            "groups; fit/calibration capture groups are disjoint from test groups"
        ),
        "held_family_minimum_rows": minimum_family_rows,
        "held_families": held_families,
        "excluded_families": {
            family: count
            for family, count in family_counts.items()
            if count < minimum_family_rows
        },
        "sources": [source.manifest for source in prepared]
        + [_source_manifest(temporal_source_id, temporal_dataset)],
        "classifier_fits": classifier_fits,
        "anomaly_orientations": orientations,
        "runs": runs,
        "summary": summary,
        "limitations": [
            "Only IoT-23 provides Schema B, so temporal transfer across organizations "
            "is not established.",
            "The temporal state is replayed over complete captures; other behavior in "
            "the same stream can influence context, but no test row enters fitting or "
            "threshold calibration.",
            "The supervised head is binary maliciousness evidence, not an attack-family "
            "classifier; anomaly evidence takes precedence for suspicious-unknown "
            "verdict accounting.",
            "File-download has too few rows for an independent quantitative claim.",
            "IoT-23 has no replay-correlated signature evidence, so signatures-only and "
            "signatures-plus-hybrid performance are not evaluated.",
            "Class sampling in supervised sources prevents representative "
            "false-alerts-per-hour estimates.",
        ],
    }
