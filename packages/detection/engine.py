from __future__ import annotations

import math
from time import perf_counter
from uuid import NAMESPACE_URL, uuid5

import numpy as np

from packages.contracts import DetectionResult, FlowEvent, SignatureEvent
from packages.detection.autoencoder import reconstruction_errors
from packages.detection.fusion import FusionConfig, FusionInput, fuse_risk
from packages.features import flow_to_vector
from packages.model_bundle import ModelBundle


class DetectionEngine:
    def __init__(self, bundle: ModelBundle) -> None:
        self.bundle = bundle
        raw = bundle.thresholds
        self.fusion = FusionConfig.from_mapping(raw)
        calibration = bundle.anomaly_calibration
        if calibration is None:
            raise ValueError(
                "model bundle lacks benign empirical anomaly calibration; promote a v3 bundle"
            )
        self.anomaly_calibration = calibration

    def detect(
        self,
        flow: FlowEvent,
        signature: SignatureEvent | None = None,
        processing_started: float | None = None,
    ) -> DetectionResult:
        started = perf_counter()
        raw = flow_to_vector(flow)
        transformed = self.bundle.preprocessor.transform(raw)
        probabilities = self.bundle.classifier.predict_proba(transformed)[0]
        classes = [str(value) for value in self.bundle.classifier.classes_]
        class_probabilities = {
            label: float(prob) for label, prob in zip(classes, probabilities, strict=True)
        }
        benign_probability = class_probabilities.get("benign", 0.0)
        known_probability = 1.0 - benign_probability
        attack_candidates = {k: v for k, v in class_probabilities.items() if k != "benign"}
        known_label = (
            max(attack_candidates, key=lambda label: attack_candidates[label])
            if attack_candidates
            else None
        )
        confidence = float(max(probabilities))

        decision = float(self.bundle.anomaly.decision_function(transformed)[0])
        if "isolation_decision_benign_median" in self.bundle.thresholds:
            center = float(self.bundle.thresholds["isolation_decision_benign_median"])
            tail = float(self.bundle.thresholds["isolation_decision_benign_p03"])
            denominator = max(center - tail, 1e-9)
            isolation_score = float(
                np.clip(((center - decision) / denominator) * self.fusion.anomaly_threshold, 0, 1)
            )
        else:
            center = float(self.bundle.thresholds.get("anomaly_decision_center", 0.0))
            scale = max(float(self.bundle.thresholds.get("anomaly_decision_scale", 0.1)), 1e-6)
            isolation_score = 1.0 / (1.0 + math.exp((decision - center) / scale))
            isolation_score = float(np.clip(isolation_score, 0.0, 1.0))

        reconstruction_error = 0.0
        reconstruction_score = 0.0
        if self.bundle.autoencoder is not None:
            reconstruction_error = float(
                reconstruction_errors(self.bundle.autoencoder, transformed)[0]
            )
            reconstruction_center = float(self.bundle.thresholds["reconstruction_error_benign_p50"])
            reconstruction_tail = float(self.bundle.thresholds["reconstruction_error_benign_p97"])
            denominator = max(reconstruction_tail - reconstruction_center, 1e-9)
            reconstruction_score = float(
                np.clip(
                    ((reconstruction_error - reconstruction_center) / denominator)
                    * self.fusion.anomaly_threshold,
                    0,
                    1,
                )
            )
        validation_scale = float(self.bundle.thresholds.get("open_set_validation_scale", 1.0))
        isolation_score = float(np.clip(isolation_score * validation_scale, 0, 1))
        reconstruction_score = float(np.clip(reconstruction_score * validation_scale, 0, 1))
        anomaly_score = max(isolation_score, reconstruction_score)
        anomaly_percentile = self.anomaly_calibration.percentile(anomaly_score)

        signature_score = 0.0
        if signature is not None:
            signature_score = {
                "informational": 0.25,
                "low": 0.45,
                "medium": 0.65,
                "high": 0.85,
                "critical": 1.0,
            }[signature.severity.value]
        fanout = float(flow.protocol_metadata.get("distinct_destination_ports", 0))
        contextual_score = min(fanout / 25.0, 1.0)
        disagreement = abs(known_probability - anomaly_score)
        outcome = fuse_risk(
            FusionInput(
                known_attack_probability=known_probability,
                classifier_confidence=confidence,
                anomaly_score=isolation_score,
                signature_score=signature_score,
                contextual_score=contextual_score,
                model_disagreement=disagreement,
                reconstruction_score=reconstruction_score,
            ),
            self.fusion,
        )
        elapsed_ms = (perf_counter() - started) * 1000
        total_ms = (
            (perf_counter() - processing_started) * 1000
            if processing_started is not None
            else elapsed_ms
        )
        return DetectionResult(
            event_id=uuid5(
                NAMESPACE_URL, f"aegisflow-detection:{flow.event_id}:{self.bundle.version}"
            ),
            flow_event_id=flow.event_id,
            known_attack_label=(
                known_label if known_probability >= self.fusion.known_threshold else None
            ),
            known_attack_probability=round(known_probability, 8),
            class_probabilities={k: round(v, 8) for k, v in class_probabilities.items()},
            classifier_confidence=round(confidence, 8),
            anomaly_score=round(anomaly_score, 8),
            anomaly_percentile=round(anomaly_percentile, 8),
            open_set_score=round(anomaly_score * _classifier_uncertainty(probabilities), 8),
            reconstruction_error=round(reconstruction_error, 8),
            reconstruction_score=round(reconstruction_score, 8),
            signature_score=signature_score,
            contextual_score=contextual_score,
            final_risk_score=outcome.risk,
            verdict=outcome.verdict,
            severity=outcome.severity,
            reason_codes=list(outcome.reasons),
            explanation=outcome.explanation,
            classifier_model_version=self.bundle.version,
            anomaly_model_version=self.bundle.version,
            threshold_version=self.fusion.version,
            inference_latency_ms=elapsed_ms,
            processing_latency_ms=total_ms,
        )


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
