from __future__ import annotations

from collections.abc import Callable, Sequence
from time import perf_counter
from uuid import NAMESPACE_URL, uuid5

import numpy as np

from packages.contracts import DetectionResult, FlowEvent, SignatureEvent
from packages.detection.hybrid import HybridBatchResult, HybridPredictor
from packages.features import flow_to_vector
from packages.model_bundle import ModelBundle


class BatchInputError(ValueError):
    """Identify one invalid row without treating a model-wide failure as bad data."""

    def __init__(self, index: int, error_code: str) -> None:
        super().__init__(f"invalid detection batch row {index}: {error_code}")
        self.index = index
        self.error_code = error_code


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
        return self.detect_batch(
            [flow],
            signatures=[signature],
            processing_started=[processing_started],
        )[0]

    def detect_batch(
        self,
        flows: Sequence[FlowEvent],
        *,
        signatures: Sequence[SignatureEvent | None] | None = None,
        processing_started: Sequence[float | None] | None = None,
        stage_observer: Callable[[str, float, int], None] | None = None,
    ) -> list[DetectionResult]:
        """Run one exact hybrid inference call for a bounded group of flows."""
        if not flows:
            raise ValueError("detection batch cannot be empty")
        rows = len(flows)
        resolved_signatures = list(signatures) if signatures is not None else [None] * rows
        resolved_starts = (
            list(processing_started) if processing_started is not None else [None] * rows
        )
        if len(resolved_signatures) != rows or len(resolved_starts) != rows:
            raise ValueError("batch metadata must align with flows")

        started = perf_counter()
        raw_rows: list[np.ndarray] = []
        signature_values: list[float] = []
        contextual_values: list[float] = []
        for index, (flow, signature) in enumerate(
            zip(flows, resolved_signatures, strict=True)
        ):
            try:
                raw_rows.append(flow_to_vector(flow))
                signature_values.append(self._signature_score(signature))
                contextual_values.append(self._contextual_score(flow))
            except (OverflowError, TypeError, ValueError) as exc:
                raise BatchInputError(index, type(exc).__name__) from exc
        raw = np.vstack(raw_rows)
        signature_scores = np.asarray(signature_values, dtype=np.float64)
        contextual_scores = np.asarray(contextual_values, dtype=np.float64)
        if stage_observer is not None:
            stage_observer("feature_conversion", (perf_counter() - started) * 1000, rows)
        batch = self.predictor.predict(
            raw,
            signature_scores=signature_scores,
            contextual_scores=contextual_scores,
            stage_observer=stage_observer,
        )
        elapsed_ms = (perf_counter() - started) * 1000
        result_started = perf_counter()
        results = [
            self._result(
                flow,
                batch,
                row,
                float(signature_scores[row]),
                float(contextual_scores[row]),
                elapsed_ms,
                resolved_starts[row],
            )
            for row, flow in enumerate(flows)
        ]
        if stage_observer is not None:
            stage_observer(
                "result_construction",
                (perf_counter() - result_started) * 1000,
                rows,
            )
        return results

    @staticmethod
    def _signature_score(signature: SignatureEvent | None) -> float:
        if signature is None:
            return 0.0
        return {
            "informational": 0.25,
            "low": 0.45,
            "medium": 0.65,
            "high": 0.85,
            "critical": 1.0,
        }[signature.severity.value]

    @staticmethod
    def _contextual_score(flow: FlowEvent) -> float:
        fanout = float(flow.protocol_metadata.get("distinct_destination_ports", 0))
        if not np.isfinite(fanout) or fanout < 0:
            raise ValueError("distinct_destination_ports must be finite and non-negative")
        return min(fanout / 25.0, 1.0)

    def _result(
        self,
        flow: FlowEvent,
        batch: HybridBatchResult,
        row: int,
        signature_score: float,
        contextual_score: float,
        inference_latency_ms: float,
        processing_started: float | None,
    ) -> DetectionResult:
        probabilities = batch.probabilities[row]
        classes = list(batch.classes)
        class_probabilities = {
            label: float(prob) for label, prob in zip(classes, probabilities, strict=True)
        }
        known_probability = float(batch.known_probabilities[row])
        known_label = batch.known_labels[row]
        confidence = float(batch.confidences[row])
        anomaly_score = float(batch.anomaly_scores[row])
        outcome = batch.outcomes[row]
        total_ms = (
            (perf_counter() - processing_started) * 1000
            if processing_started is not None
            else inference_latency_ms
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
            anomaly_percentile=round(float(batch.anomaly_percentiles[row]), 8),
            open_set_score=round(float(batch.open_set_scores[row]), 8),
            reconstruction_error=round(float(batch.reconstruction_errors[row]), 8),
            reconstruction_score=round(float(batch.reconstruction_scores[row]), 8),
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
            inference_latency_ms=inference_latency_ms,
            processing_latency_ms=total_ms,
        )
