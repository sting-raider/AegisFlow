from __future__ import annotations

import math
import os
import socket
from collections import deque
from collections.abc import Callable
from threading import Event, Lock, Thread
from time import perf_counter

from pydantic import ValidationError
from redis.exceptions import RedisError
from sqlalchemy.exc import SQLAlchemyError

from apps.api.database import Repository
from packages.common import log_event, service_logger
from packages.common.bus import MessageTooLargeError, RedisStreamBus, safe_dead_letter
from packages.contracts import DetectionResult, FlowEvent, SignatureEvent
from packages.incidents import DriftEvent, RuntimeDriftMonitor


class DetectionConsumer:
    def __init__(
        self,
        repository: Repository,
        redis_url: str,
        *,
        bus: RedisStreamBus | None = None,
        database_attempts: int = 3,
        retry_base_seconds: float = 0.1,
        on_database_error: Callable[[], None] | None = None,
        on_flow_received: Callable[[], None] | None = None,
        on_flow_validated: Callable[[], None] | None = None,
        on_flow_rejected: Callable[[str], None] | None = None,
        on_flow_dropped: Callable[[str], None] | None = None,
        on_signature_event: Callable[[], None] | None = None,
        on_processing_latency: Callable[[float], None] | None = None,
        on_detection_result: Callable[[DetectionResult, bool], None] | None = None,
        on_backpressure: Callable[[], None] | None = None,
        drift_monitor: RuntimeDriftMonitor | None = None,
        on_drift_event: Callable[[DriftEvent], None] | None = None,
    ) -> None:
        self.repository = repository
        self.on_backpressure = on_backpressure
        configured_capacity = int(os.getenv("AEGISFLOW_STREAM_MAXLEN", "100000"))
        self.bus = bus or RedisStreamBus(
            redis_url,
            maxlen=configured_capacity,
            max_payload_bytes=int(
                os.getenv("AEGISFLOW_STREAM_MAX_PAYLOAD_BYTES", "1048576")
            ),
            claim_idle_ms=int(os.getenv("AEGISFLOW_PENDING_IDLE_MS", "30000")),
            on_backpressure=self._record_backpressure,
        )
        self.queue_capacity = int(getattr(self.bus, "maxlen", configured_capacity))
        self.database_attempts = max(1, database_attempts)
        self.retry_base_seconds = max(0.0, retry_base_seconds)
        self.on_database_error = on_database_error
        self.on_flow_received = on_flow_received
        self.on_flow_validated = on_flow_validated
        self.on_flow_rejected = on_flow_rejected
        self.on_flow_dropped = on_flow_dropped
        self.on_signature_event = on_signature_event
        self.on_processing_latency = on_processing_latency
        self.on_detection_result = on_detection_result
        self.drift_monitor = drift_monitor
        self.on_drift_event = on_drift_event
        self.queue_status = {
            "pending": 0,
            "lag": 0,
            "consumers": 0,
            "capacity": self.queue_capacity,
            "utilization": 0.0,
            "backpressure": False,
            "backpressure_events": 0,
        }
        self._telemetry_lock = Lock()
        self._received_times: deque[float] = deque(maxlen=10_000)
        self.received_total = 0
        self.validated_total = 0
        self.rejected_total = 0
        self.dropped_total = 0
        self.signature_total = 0
        self.backpressure_events = 0
        self._backpressure_active = False
        self.last_processing_latency_ms: float | None = None
        self.logger = service_logger("api-consumer")
        self.stop_event = Event()
        self.thread = Thread(target=self._run, name="detection-consumer", daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=5)

    def _run(self) -> None:
        consumer = f"api-{socket.gethostname()}-{os.getpid()}"
        redis_retry_seconds = 0.25
        while not self.stop_event.is_set():
            try:
                for message_id, envelope in self.bus.consume(
                    "aegisflow:detections", "api-core", consumer, block_ms=1000
                ):
                    self.process_message(message_id, envelope)
                self._update_queue_status()
                redis_retry_seconds = 0.25
            except RedisError as exc:
                log_event(
                    self.logger,
                    "redis_unavailable",
                    level="warning",
                    error_code=type(exc).__name__,
                )
                if self.stop_event.wait(redis_retry_seconds):
                    break
                redis_retry_seconds = min(redis_retry_seconds * 2, 5.0)

    def process_message(self, message_id: str, envelope: dict[str, object]) -> bool:
        """Persist one detection and acknowledge only durable or quarantined outcomes."""
        started = perf_counter()
        with self._telemetry_lock:
            self.received_total += 1
            self._received_times.append(started)
        if self.on_flow_received is not None:
            self.on_flow_received()
        try:
            return self._process_message(message_id, envelope)
        finally:
            elapsed = perf_counter() - started
            with self._telemetry_lock:
                self.last_processing_latency_ms = elapsed * 1000
            if self.on_processing_latency is not None:
                self.on_processing_latency(elapsed)

    def _process_message(self, message_id: str, envelope: dict[str, object]) -> bool:
        try:
            flow = FlowEvent.model_validate(envelope["flow"])
            detection = DetectionResult.model_validate(envelope["detection"])
            signature = (
                SignatureEvent.model_validate(envelope["signature"])
                if envelope.get("signature")
                else None
            )
        except (KeyError, TypeError, ValueError, ValidationError) as exc:
            error_code = type(exc).__name__
            with self._telemetry_lock:
                self.rejected_total += 1
            if self.on_flow_rejected is not None:
                self.on_flow_rejected(error_code)
            try:
                self.bus.publish(
                    "aegisflow:dead-letter",
                    safe_dead_letter("aegisflow:detections", envelope, error_code),
                )
            except MessageTooLargeError:
                with self._telemetry_lock:
                    self.dropped_total += 1
                if self.on_flow_dropped is not None:
                    self.on_flow_dropped("dead_letter_too_large")
                return False
            self.bus.acknowledge("aegisflow:detections", "api-core", message_id)
            log_event(
                self.logger,
                "detection_event_rejected",
                level="error",
                error_code=error_code,
            )
            return True

        with self._telemetry_lock:
            self.validated_total += 1
            if signature is not None:
                self.signature_total += 1
        if self.on_flow_validated is not None:
            self.on_flow_validated()
        if signature is not None and self.on_signature_event is not None:
            self.on_signature_event()

        monitor = self.drift_monitor
        novelty_required = monitor is not None or self.on_detection_result is not None
        is_new_detection: bool | None = None if novelty_required else False
        pending_drift_events: tuple[DriftEvent, ...] | None = None
        for attempt in range(self.database_attempts):
            try:
                if is_new_detection is None:
                    is_new_detection = not self.repository.detection_exists(
                        str(detection.event_id)
                    )
                alert_id = self.repository.ingest(flow, detection, signature)
                if is_new_detection and monitor is not None:
                    if pending_drift_events is None:
                        pending_drift_events = monitor.observe(flow, detection)
                    for event in pending_drift_events:
                        if self.repository.record_drift_event(event) and self.on_drift_event:
                            self.on_drift_event(event)
                self.bus.acknowledge("aegisflow:detections", "api-core", message_id)
                if is_new_detection and self.on_detection_result is not None:
                    self.on_detection_result(detection, alert_id is not None)
                log_event(
                    self.logger,
                    "detection_persisted",
                    flow_id=str(flow.event_id),
                    model_version=detection.classifier_model_version,
                )
                return True
            except SQLAlchemyError as exc:
                if self.on_database_error is not None:
                    self.on_database_error()
                if attempt + 1 == self.database_attempts:
                    log_event(
                        self.logger,
                        "database_retry_exhausted",
                        level="error",
                        flow_id=str(flow.event_id),
                        model_version=detection.classifier_model_version,
                        error_code=type(exc).__name__,
                    )
                    return False
                delay = self.retry_base_seconds * (2**attempt)
                if self.stop_event.wait(delay):
                    return False
        return False

    def _record_backpressure(self, _stream: str) -> None:
        with self._telemetry_lock:
            self.backpressure_events += 1
        if self.on_backpressure is not None:
            self.on_backpressure()

    def _update_queue_status(self) -> None:
        status = self.bus.group_status("aegisflow:detections", "api-core")
        depth = status["pending"] + status["lag"]
        utilization = min(1.0, depth / self.queue_capacity)
        try:
            threshold = float(os.getenv("AEGISFLOW_BACKPRESSURE_THRESHOLD", "0.8"))
        except ValueError:
            threshold = 0.8
        if not math.isfinite(threshold):
            threshold = 0.8
        threshold = max(0.1, min(1.0, threshold))
        backpressure = utilization >= threshold
        if backpressure and not self._backpressure_active:
            self._record_backpressure("aegisflow:detections")
        self._backpressure_active = backpressure
        self.queue_status = {
            **status,
            "capacity": self.queue_capacity,
            "utilization": utilization,
            "backpressure": backpressure,
            "backpressure_events": self.backpressure_events,
        }

    def telemetry(self) -> dict[str, int | float | None]:
        now = perf_counter()
        with self._telemetry_lock:
            while self._received_times and now - self._received_times[0] > 60:
                self._received_times.popleft()
            elapsed = max(1.0, now - self._received_times[0]) if self._received_times else 1.0
            return {
                "received_total": self.received_total,
                "validated_total": self.validated_total,
                "rejected_total": self.rejected_total,
                "dropped_total": self.dropped_total,
                "signature_total": self.signature_total,
                "backpressure_events": self.backpressure_events,
                "throughput_per_second": len(self._received_times) / elapsed,
                "processing_latency_ms": self.last_processing_latency_ms,
            }
