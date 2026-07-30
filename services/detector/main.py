from __future__ import annotations

import os
import socket
from pathlib import Path

from pydantic import ValidationError

from packages.common.bus import RedisStreamBus
from packages.contracts import FlowEvent, SignatureEvent
from packages.detection import DetectionEngine
from packages.model_bundle import load_production_bundle

FLOW_STREAM = "aegisflow:flows"
DETECTION_STREAM = "aegisflow:detections"
DEAD_STREAM = "aegisflow:dead-letter"
GROUP = "detectors"


def run() -> None:
    bus = RedisStreamBus(os.getenv("AEGISFLOW_REDIS_URL", "redis://localhost:6379/0"))
    bundle = load_production_bundle(Path(os.getenv("AEGISFLOW_MODEL_REGISTRY", "models/registry")))
    engine = DetectionEngine(bundle)
    consumer = os.getenv("AEGISFLOW_CONSUMER_NAME", socket.gethostname())
    while True:
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
                    DEAD_STREAM, {"source": FLOW_STREAM, "error": str(exc), "event": envelope}
                )
                bus.acknowledge(FLOW_STREAM, GROUP, message_id)


if __name__ == "__main__":
    run()
