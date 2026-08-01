from __future__ import annotations

from time import perf_counter
from uuid import NAMESPACE_URL, uuid5

from packages.contracts import DetectionResult, FlowEvent, SignatureEvent
from packages.detection.hybrid import HybridPredictor
from packages.features import flow_to_vector
from packages.model_bundle import ModelBundle


class DetectionEngine:
    def __init__(self, bundle: ModelBundle) -> None:
        self.bundle = bundle
        self.predictor = HybridPredictor(bundle)
        self.fusion = self.predictor.fusion

    def detect(
        self,
        flow: FlowEvent,
        signature: SignatureEvent | None = None,
        processing_started: float | None = None,
    ) -> DetectionResult:
        started = perf_counter()
        raw = flow_to_vector(flow)
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
        batch = self.predictor.predict(
            raw,
            signature_scores=[signature_score],
            contextual_scores=[contextual_score],
        )
        probabilities = batch.probabilities[0]
        classes = list(batch.classes)
        class_probabilities = {
            label: float(prob) for label, prob in zip(classes, probabilities, strict=True)
        }
        known_probability = float(batch.known_probabilities[0])
        known_label = batch.known_labels[0]
        confidence = float(batch.confidences[0])
        anomaly_score = float(batch.anomaly_scores[0])
        outcome = batch.outcomes[0]
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
            anomaly_percentile=round(float(batch.anomaly_percentiles[0]), 8),
            open_set_score=round(float(batch.open_set_scores[0]), 8),
            reconstruction_error=round(float(batch.reconstruction_errors[0]), 8),
            reconstruction_score=round(float(batch.reconstruction_scores[0]), 8),
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
