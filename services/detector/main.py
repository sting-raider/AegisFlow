from __future__ import annotations

import os
import signal
import socket
from pathlib import Path
from threading import Event
from time import perf_counter

from redis.exceptions import RedisError

from packages.common import log_event, service_logger
from packages.common.bus import RedisStreamBus
from packages.detection import DetectionEngine
from packages.model_bundle import load_production_bundle
from services.detector.worker import FLOW_STREAM, GROUP, DetectorWorker

LOGGER = service_logger("detector")


def run() -> None:
    stop_event = Event()

    def request_stop(_signum: int, _frame: object) -> None:
        stop_event.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    bus = RedisStreamBus(
        os.getenv("AEGISFLOW_REDIS_URL", "redis://localhost:6379/0"),
        maxlen=int(os.getenv("AEGISFLOW_STREAM_MAXLEN", "100000")),
        max_payload_bytes=int(os.getenv("AEGISFLOW_STREAM_MAX_PAYLOAD_BYTES", "1048576")),
        claim_idle_ms=int(os.getenv("AEGISFLOW_PENDING_IDLE_MS", "30000")),
        on_backpressure=lambda stream: log_event(
            LOGGER, "queue_capacity_pressure", level="warning", error_code=stream
        ),
    )
    bundle = load_production_bundle(Path(os.getenv("AEGISFLOW_MODEL_REGISTRY", "models/registry")))
    engine = DetectionEngine(bundle)
    worker = DetectorWorker(bus=bus, engine=engine)
    consumer = os.getenv(
        "AEGISFLOW_CONSUMER_NAME", f"{socket.gethostname()}-{os.getpid()}"
    )
    batch_size = max(1, min(int(os.getenv("AEGISFLOW_DETECTOR_BATCH_SIZE", "64")), 512))
    batch_wait_ms = max(
        1, min(int(os.getenv("AEGISFLOW_DETECTOR_BATCH_WAIT_MS", "250")), 5_000)
    )
    redis_retry_seconds = 0.25
    while not stop_event.is_set():
        try:
            messages = bus.consume_batch(
                FLOW_STREAM,
                GROUP,
                consumer,
                count=batch_size,
                block_ms=batch_wait_ms,
            )
            if messages:
                started = perf_counter()
                result = worker.process_batch(messages)
                log_event(
                    LOGGER,
                    "detection_batch_published",
                    model_version=bundle.version,
                    batch_size=result.received,
                    published_count=result.published,
                    rejected_count=result.rejected,
                    duration_ms=(perf_counter() - started) * 1000,
                )
            redis_retry_seconds = 0.25
        except RedisError as exc:
            log_event(
                LOGGER,
                "redis_unavailable",
                level="warning",
                model_version=str(bundle.manifest["version"]),
                error_code=type(exc).__name__,
            )
            if stop_event.wait(redis_retry_seconds):
                break
            redis_retry_seconds = min(redis_retry_seconds * 2, 5.0)


if __name__ == "__main__":
    run()
