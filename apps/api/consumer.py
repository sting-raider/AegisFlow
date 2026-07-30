from __future__ import annotations

import os
import socket
from threading import Event, Thread

from pydantic import ValidationError

from apps.api.database import Repository
from packages.common.bus import RedisStreamBus
from packages.contracts import DetectionResult, FlowEvent, SignatureEvent


class DetectionConsumer:
    def __init__(self, repository: Repository, redis_url: str) -> None:
        self.repository = repository
        self.bus = RedisStreamBus(redis_url)
        self.stop_event = Event()
        self.thread = Thread(target=self._run, name="detection-consumer", daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=5)

    def _run(self) -> None:
        consumer = f"api-{socket.gethostname()}-{os.getpid()}"
        while not self.stop_event.is_set():
            for message_id, envelope in self.bus.consume(
                "aegisflow:detections", "api-core", consumer, block_ms=1000
            ):
                try:
                    flow = FlowEvent.model_validate(envelope["flow"])
                    detection = DetectionResult.model_validate(envelope["detection"])
                    signature = (
                        SignatureEvent.model_validate(envelope["signature"])
                        if envelope.get("signature")
                        else None
                    )
                    self.repository.ingest(flow, detection, signature)
                except (KeyError, TypeError, ValueError, ValidationError) as exc:
                    self.bus.publish(
                        "aegisflow:dead-letter",
                        {
                            "source": "aegisflow:detections",
                            "error": str(exc),
                            "event": envelope,
                        },
                    )
                finally:
                    self.bus.acknowledge("aegisflow:detections", "api-core", message_id)
