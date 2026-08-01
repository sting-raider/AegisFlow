from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np

from packages.detection.autoencoder import reconstruction_errors
from packages.detection.fusion import FusionConfig, FusionInput, FusionOutcome, fuse_risk
from packages.features.registry import FEATURE_NAMES
from packages.model_bundle import ModelBundle


@dataclass(frozen=True)
class HybridBatchResult:
    classes: tuple[str, ...]
    probabilities: np.ndarray
    known_probabilities: np.ndarray
    known_labels: tuple[str | None, ...]
    confidences: np.ndarray
    isolation_scores: np.ndarray
    reconstruction_errors: np.ndarray
    reconstruction_scores: np.ndarray
    anomaly_scores: np.ndarray
    anomaly_percentiles: np.ndarray
    open_set_scores: np.ndarray
    outcomes: tuple[FusionOutcome, ...]


class HybridPredictor:
    """The shared deployed hybrid inference path for runtime and offline evaluation."""

    def __init__(self, bundle: ModelBundle) -> None:
        calibration = bundle.anomaly_calibration
        if calibration is None:
            raise ValueError(
                "model bundle lacks benign empirical anomaly calibration; promote a v3 bundle"
            )
        autoencoder = bundle.autoencoder
        if autoencoder is None:
            raise ValueError("exact hybrid inference requires an autoencoder artifact")
        self.bundle = bundle
        self.fusion = FusionConfig.from_mapping(bundle.thresholds)
        self.anomaly_calibration = calibration
        self.autoencoder = autoencoder

    def predict(
        self,
        raw_features: np.ndarray,
        *,
        signature_scores: np.ndarray | Sequence[float] | None = None,
        contextual_scores: np.ndarray | Sequence[float] | None = None,
    ) -> HybridBatchResult:
        raw = np.asarray(raw_features, dtype=np.float64)
        if raw.ndim == 1:
            raw = raw.reshape(1, -1)
        if raw.ndim != 2 or raw.shape[1] != len(FEATURE_NAMES) or not len(raw):
            raise ValueError("hybrid inference requires a non-empty canonical feature matrix")
        if not np.all(np.isfinite(raw)):
            raise ValueError("hybrid inference refuses non-finite features")
        rows = len(raw)
        signatures = _optional_signal(signature_scores, rows, "signature")
        contexts = _optional_signal(contextual_scores, rows, "contextual")

        transformed = self.bundle.preprocessor.transform(raw)
        probabilities = np.asarray(
            self.bundle.classifier.predict_proba(transformed), dtype=np.float64
        )
        classes = tuple(str(value) for value in self.bundle.classifier.classes_)
        benign_indices = [index for index, label in enumerate(classes) if label == "benign"]
        if len(benign_indices) != 1:
            raise ValueError("hybrid classifier must contain exactly one benign class")
        benign_index = benign_indices[0]
        known_probabilities = 1.0 - probabilities[:, benign_index]
        confidences = probabilities.max(axis=1)
        attack_indices = [index for index, label in enumerate(classes) if label != "benign"]
        known_labels = tuple(
            classes[max(attack_indices, key=lambda index: probabilities[row, index])]
            if attack_indices
            else None
            for row in range(rows)
        )

        decisions = np.asarray(self.bundle.anomaly.decision_function(transformed), dtype=np.float64)
        isolation_scores = self._isolation_scores(decisions)
        raw_reconstruction_errors = reconstruction_errors(self.autoencoder, transformed)
        reconstruction_scores = self._reconstruction_scores(raw_reconstruction_errors)
        validation_scale = float(self.bundle.thresholds.get("open_set_validation_scale", 1.0))
        isolation_scores = np.clip(isolation_scores * validation_scale, 0.0, 1.0)
        reconstruction_scores = np.clip(reconstruction_scores * validation_scale, 0.0, 1.0)
        anomaly_scores = np.maximum(isolation_scores, reconstruction_scores)
        anomaly_percentiles = np.asarray(
            [self.anomaly_calibration.percentile(float(score)) for score in anomaly_scores]
        )
        open_set_scores = np.asarray(
            [
                float(score) * _classifier_uncertainty(probability)
                for score, probability in zip(anomaly_scores, probabilities, strict=True)
            ]
        )
        outcomes = tuple(
            fuse_risk(
                FusionInput(
                    known_attack_probability=float(known_probability),
                    classifier_confidence=float(confidence),
                    anomaly_score=float(isolation),
                    signature_score=float(signature),
                    contextual_score=float(context),
                    model_disagreement=abs(float(known_probability) - float(anomaly)),
                    reconstruction_score=float(reconstruction),
                ),
                self.fusion,
            )
            for (
                known_probability,
                confidence,
                isolation,
                signature,
                context,
                anomaly,
                reconstruction,
            ) in zip(
                known_probabilities,
                confidences,
                isolation_scores,
                signatures,
                contexts,
                anomaly_scores,
                reconstruction_scores,
                strict=True,
            )
        )
        return HybridBatchResult(
            classes,
            probabilities,
            known_probabilities,
            known_labels,
            confidences,
            isolation_scores,
            np.asarray(raw_reconstruction_errors, dtype=np.float64),
            reconstruction_scores,
            anomaly_scores,
            anomaly_percentiles,
            open_set_scores,
            outcomes,
        )

    def _isolation_scores(self, decisions: np.ndarray) -> np.ndarray:
        thresholds = self.bundle.thresholds
        normalization_tail = float(
            thresholds.get("anomaly_normalization_tail_score", self.fusion.anomaly_threshold)
        )
        if "isolation_decision_benign_median" in thresholds:
            center = float(thresholds["isolation_decision_benign_median"])
            tail = float(thresholds["isolation_decision_benign_p03"])
            denominator = max(center - tail, 1e-9)
            return np.clip(
                ((center - decisions) / denominator) * normalization_tail,
                0.0,
                1.0,
            )
        center = float(thresholds.get("anomaly_decision_center", 0.0))
        scale = max(float(thresholds.get("anomaly_decision_scale", 0.1)), 1e-6)
        return np.clip(1.0 / (1.0 + np.exp((decisions - center) / scale)), 0.0, 1.0)

    def _reconstruction_scores(self, errors: np.ndarray) -> np.ndarray:
        normalization_tail = float(
            self.bundle.thresholds.get(
                "anomaly_normalization_tail_score", self.fusion.anomaly_threshold
            )
        )
        center = float(self.bundle.thresholds["reconstruction_error_benign_p50"])
        tail = float(self.bundle.thresholds["reconstruction_error_benign_p97"])
        denominator = max(tail - center, 1e-9)
        return np.clip(
            ((errors - center) / denominator) * normalization_tail,
            0.0,
            1.0,
        )


def _optional_signal(
    values: np.ndarray | Sequence[float] | None, rows: int, name: str
) -> np.ndarray:
    if values is None:
        return np.zeros(rows, dtype=np.float64)
    result = np.asarray(values, dtype=np.float64).reshape(-1)
    if len(result) != rows or not np.all(np.isfinite(result)):
        raise ValueError(f"{name} scores must align with inference rows and be finite")
    if np.any(result < 0) or np.any(result > 1):
        raise ValueError(f"{name} scores must be in [0, 1]")
    return result


def _classifier_uncertainty(probabilities: np.ndarray) -> float:
    if len(probabilities) <= 1:
        return 1.0 - float(probabilities[0])
    ordered = np.sort(probabilities)
    margin_uncertainty = 1.0 - float(ordered[-1] - ordered[-2])
    entropy = -float(np.sum(probabilities * np.log(np.clip(probabilities, 1e-12, 1.0))))
    normalized_entropy = entropy / math.log(len(probabilities))
    return float(
        np.clip(max(1.0 - float(ordered[-1]), margin_uncertainty, normalized_entropy), 0, 1)
    )
