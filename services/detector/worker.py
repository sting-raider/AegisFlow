from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter

from pydantic import ValidationError

from packages.common import log_event, service_logger
from packages.common.bus import (
    BatchMessageTooLargeError,
    RedisStreamBus,
    safe_dead_letter,
    stream_error_code,
)
from packages.contracts import FlowEvent, SignatureEvent
from packages.detection import BatchInputError, DetectionEngine

FLOW_STREAM = "aegisflow:flows"
DETECTION_STREAM = "aegisflow:detections"
DEAD_STREAM = "aegisflow:dead-letter"
GROUP = "detectors"


@dataclass(frozen=True)
class BatchProcessingResult:
    received: int
    published: int
    rejected: int


@dataclass(frozen=True)
class _WorkItem:
    message_id: str
    envelope: dict[str, object]
    flow: FlowEvent
    signature: SignatureEvent | None


class DetectorWorker:
    """Validate, batch-infer, publish, then acknowledge Redis flow messages."""

    def __init__(self, *, bus: RedisStreamBus, engine: DetectionEngine) -> None:
        self.bus = bus
        self.engine = engine
        self.logger = service_logger("detector")

    def process_batch(
        self, messages: list[tuple[str, dict[str, object]]]
    ) -> BatchProcessingResult:
        processing_started = perf_counter()
        work: list[_WorkItem] = []
        rejected = 0
        for message_id, envelope in messages:
            try:
                flow = FlowEvent.model_validate(envelope["flow"])
                signature = (
                    SignatureEvent.model_validate(envelope["signature"])
                    if envelope.get("signature")
                    else None
                )
            except (KeyError, TypeError, ValueError, ValidationError) as exc:
                self._reject(
                    message_id,
                    envelope,
                    stream_error_code(envelope, type(exc).__name__),
                )
                rejected += 1
                continue
            work.append(_WorkItem(message_id, envelope, flow, signature))

        published = 0
        while work:
            try:
                detections = self.engine.detect_batch(
                    [item.flow for item in work],
                    signatures=[item.signature for item in work],
                    processing_started=[processing_started] * len(work),
                )
            except BatchInputError as exc:
                if exc.index < 0 or exc.index >= len(work):
                    raise RuntimeError(
                        "detection engine returned an invalid batch row index"
                    ) from exc
                invalid = work.pop(exc.index)
                self._reject(invalid.message_id, invalid.envelope, exc.error_code)
                rejected += 1
                continue

            payloads = [
                {
                    "flow": item.flow.model_dump(mode="json"),
                    "signature": (
                        item.signature.model_dump(mode="json")
                        if item.signature is not None
                        else None
                    ),
                    "detection": detection.model_dump(mode="json"),
                }
                for item, detection in zip(work, detections, strict=True)
            ]
            while payloads:
                try:
                    self.bus.publish_batch(DETECTION_STREAM, payloads)
                except BatchMessageTooLargeError as exc:
                    if exc.index < 0 or exc.index >= len(work):
                        raise RuntimeError(
                            "Redis bus returned an invalid publish batch index"
                        ) from exc
                    invalid = work.pop(exc.index)
                    payloads.pop(exc.index)
                    self._reject(invalid.message_id, invalid.envelope, type(exc).__name__)
                    rejected += 1
                    continue
                self.bus.acknowledge_many(
                    FLOW_STREAM,
                    GROUP,
                    [item.message_id for item in work],
                )
                published += len(work)
                break
            break

        return BatchProcessingResult(
            received=len(messages),
            published=published,
            rejected=rejected,
        )

    def _reject(
        self,
        message_id: str,
        envelope: dict[str, object],
        error_code: str,
    ) -> None:
        self.bus.publish(DEAD_STREAM, safe_dead_letter(FLOW_STREAM, envelope, error_code))
        self.bus.acknowledge(FLOW_STREAM, GROUP, message_id)
        log_event(
            self.logger,
            "flow_processing_rejected",
            level="error",
            model_version=self.engine.bundle.version,
            error_code=error_code,
        )
