from __future__ import annotations

import math
from time import perf_counter
from uuid import NAMESPACE_URL, uuid5

import numpy as np

from packages.contracts import DetectionResult, FlowEvent, SignatureEvent
from packages.detection.fusion import FusionConfig, FusionInput, fuse_risk
from packages.features import flow_to_vector
from packages.model_bundle import ModelBundle


class DetectionEngine:
    def __init__(self, bundle: ModelBundle) -> None:
        self.bundle = bundle
        raw = bundle.thresholds
        self.fusion = FusionConfig(
            version=str(raw.get("version", "1.0.0")),
            known_threshold=float(raw.get("known_threshold", 0.72)),
            anomaly_threshold=float(raw.get("anomaly_threshold", 0.70)),
        )

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
        center = float(self.bundle.thresholds.get("anomaly_decision_center", 0.0))
        scale = max(float(self.bundle.thresholds.get("anomaly_decision_scale", 0.1)), 1e-6)
        anomaly_score = 1.0 / (1.0 + math.exp((decision - center) / scale))
        anomaly_score = float(np.clip(anomaly_score, 0.0, 1.0))

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
                anomaly_score=anomaly_score,
                signature_score=signature_score,
                contextual_score=contextual_score,
                model_disagreement=disagreement,
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
            known_attack_label=known_label if known_probability >= 0.5 else None,
            known_attack_probability=round(known_probability, 8),
            class_probabilities={k: round(v, 8) for k, v in class_probabilities.items()},
            classifier_confidence=round(confidence, 8),
            anomaly_score=round(anomaly_score, 8),
            anomaly_percentile=round(anomaly_score, 8),
            open_set_score=round(anomaly_score * (1.0 - confidence), 8),
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
