from __future__ import annotations

import os
import signal
import socket
from pathlib import Path
from threading import Event

from pydantic import ValidationError
from redis.exceptions import RedisError

from packages.common.bus import RedisStreamBus
from packages.contracts import FlowEvent, SignatureEvent
from packages.detection import DetectionEngine
from packages.model_bundle import load_production_bundle

FLOW_STREAM = "aegisflow:flows"
DETECTION_STREAM = "aegisflow:detections"
DEAD_STREAM = "aegisflow:dead-letter"
GROUP = "detectors"


def run() -> None:
    stop_event = Event()

    def request_stop(_signum: int, _frame: object) -> None:
        stop_event.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    bus = RedisStreamBus(
        os.getenv("AEGISFLOW_REDIS_URL", "redis://localhost:6379/0"),
        claim_idle_ms=int(os.getenv("AEGISFLOW_PENDING_IDLE_MS", "30000")),
    )
    bundle = load_production_bundle(Path(os.getenv("AEGISFLOW_MODEL_REGISTRY", "models/registry")))
    engine = DetectionEngine(bundle)
    consumer = os.getenv("AEGISFLOW_CONSUMER_NAME", socket.gethostname())
    redis_retry_seconds = 0.25
    while not stop_event.is_set():
        try:
            for message_id, envelope in bus.consume(FLOW_STREAM, GROUP, consumer):
                try:
                    flow = FlowEvent.model_validate(envelope["flow"])
                    signature = (
                        SignatureEvent.model_validate(envelope["signature"])
                        if envelope.get("signature")
                        else None
                    )
                    detection = engine.detect(flow, signature)
                    bus.publish(
                        DETECTION_STREAM,
                        {
                            "flow": flow.model_dump(mode="json"),
                            "signature": signature.model_dump(mode="json") if signature else None,
                            "detection": detection.model_dump(mode="json"),
                        },
                    )
                    bus.acknowledge(FLOW_STREAM, GROUP, message_id)
                except (KeyError, TypeError, ValueError, ValidationError) as exc:
                    bus.publish(
                        DEAD_STREAM,
                        {"source": FLOW_STREAM, "error": str(exc), "event": envelope},
                    )
                    bus.acknowledge(FLOW_STREAM, GROUP, message_id)
            redis_retry_seconds = 0.25
        except RedisError:
            if stop_event.wait(redis_retry_seconds):
                break
            redis_retry_seconds = min(redis_retry_seconds * 2, 5.0)


if __name__ == "__main__":
    run()
