from __future__ import annotations

import os
import socket
from collections.abc import Callable
from threading import Event, Thread

from pydantic import ValidationError
from redis.exceptions import RedisError
from sqlalchemy.exc import SQLAlchemyError

from apps.api.database import Repository
from packages.common.bus import RedisStreamBus
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
        drift_monitor: RuntimeDriftMonitor | None = None,
        on_drift_event: Callable[[DriftEvent], None] | None = None,
    ) -> None:
        self.repository = repository
        self.bus = bus or RedisStreamBus(
            redis_url,
            claim_idle_ms=int(os.getenv("AEGISFLOW_PENDING_IDLE_MS", "30000")),
        )
        self.database_attempts = max(1, database_attempts)
        self.retry_base_seconds = max(0.0, retry_base_seconds)
        self.on_database_error = on_database_error
        self.drift_monitor = drift_monitor
        self.on_drift_event = on_drift_event
        self.queue_status = {"pending": 0, "lag": 0, "consumers": 0}
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
                self.queue_status = self.bus.group_status("aegisflow:detections", "api-core")
                redis_retry_seconds = 0.25
            except RedisError:
                if self.stop_event.wait(redis_retry_seconds):
                    break
                redis_retry_seconds = min(redis_retry_seconds * 2, 5.0)

    def process_message(self, message_id: str, envelope: dict[str, object]) -> bool:
        """Persist one detection and acknowledge only durable or quarantined outcomes."""
        try:
            flow = FlowEvent.model_validate(envelope["flow"])
            detection = DetectionResult.model_validate(envelope["detection"])
            signature = (
                SignatureEvent.model_validate(envelope["signature"])
                if envelope.get("signature")
                else None
            )
        except (KeyError, TypeError, ValueError, ValidationError) as exc:
            self.bus.publish(
                "aegisflow:dead-letter",
                {
                    "source": "aegisflow:detections",
                    "error": str(exc),
                    "event": envelope,
                },
            )
            self.bus.acknowledge("aegisflow:detections", "api-core", message_id)
            return True

        monitor = self.drift_monitor
        is_new_detection: bool | None = False if monitor is None else None
        pending_drift_events: tuple[DriftEvent, ...] | None = None
        for attempt in range(self.database_attempts):
            try:
                if is_new_detection is None:
                    is_new_detection = not self.repository.detection_exists(
                        str(detection.event_id)
                    )
                self.repository.ingest(flow, detection, signature)
                if is_new_detection:
                    if pending_drift_events is None:
                        assert monitor is not None
                        pending_drift_events = monitor.observe(flow, detection)
                    for event in pending_drift_events:
                        if self.repository.record_drift_event(event) and self.on_drift_event:
                            self.on_drift_event(event)
                self.bus.acknowledge("aegisflow:detections", "api-core", message_id)
                return True
            except SQLAlchemyError:
                if self.on_database_error is not None:
                    self.on_database_error()
                if attempt + 1 == self.database_attempts:
                    return False
                delay = self.retry_base_seconds * (2**attempt)
                if self.stop_event.wait(delay):
                    return False
        return False
