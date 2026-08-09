from __future__ import annotations

import argparse
import json
import os
import platform
from datetime import UTC, datetime, timedelta
from pathlib import Path
from statistics import median, quantiles
from time import perf_counter, sleep
from typing import cast
from urllib.parse import urlsplit
from uuid import NAMESPACE_URL, uuid4, uuid5

from sqlalchemy import func, select

from apps.api.database import DetectionRow, FlowRow, Repository
from packages.common.bus import RedisStreamBus
from services.sensor import DemoAdapter

FLOW_STREAM = "aegisflow:flows"
ALLOWED_BENCHMARK_HOSTS = {"127.0.0.1", "::1", "localhost", "postgres", "redis"}


def _require_local_service_url(value: str, description: str) -> str:
    host = urlsplit(value).hostname
    if host not in ALLOWED_BENCHMARK_HOSTS:
        raise ValueError(f"{description} must target localhost or the AegisFlow Compose network")
    return value


def _percentile(values: list[float], index: int) -> float:
    if len(values) == 1:
        return values[0]
    return quantiles(values, n=100, method="inclusive")[index - 1]


def _persisted(
    repository: Repository,
    sensor_id: str,
) -> tuple[int, list[dict[str, object]]]:
    with repository.session() as session:
        flow_count = int(
            session.scalar(
                select(func.count()).select_from(FlowRow).where(FlowRow.sensor_id == sensor_id)
            )
            or 0
        )
        detection_payloads = list(
            session.scalars(
                select(DetectionRow.payload)
                .join(FlowRow, DetectionRow.flow_event_id == FlowRow.event_id)
                .where(FlowRow.sensor_id == sensor_id)
            )
        )
    return flow_count, detection_payloads


def run_pipeline_benchmark(
    *,
    total: int,
    redis_url: str,
    database_url: str,
    timeout_seconds: float = 120.0,
    publish_batch_size: int = 64,
) -> dict[str, object]:
    if total < 2:
        raise ValueError("pipeline benchmark requires at least two flows")
    if publish_batch_size < 1 or publish_batch_size > 512:
        raise ValueError("publish batch size must be in [1, 512]")
    redis_url = _require_local_service_url(redis_url, "Redis URL")
    database_url = _require_local_service_url(database_url, "database URL")
    bus = RedisStreamBus(redis_url)
    repository = Repository(database_url)
    fixtures = list(DemoAdapter().flows())
    run_id = f"benchmark-{uuid4().hex[:12]}"
    generated_at = datetime.now(UTC)
    envelopes: list[dict[str, object]] = []
    for index in range(total):
        source = fixtures[index % len(fixtures)]
        timestamp_start = generated_at + timedelta(microseconds=index * 100)
        flow = source.model_copy(
            update={
                "event_id": uuid5(
                    NAMESPACE_URL,
                    f"aegisflow-pipeline-benchmark:{run_id}:{index}",
                ),
                "sensor_id": run_id,
                "timestamp_start": timestamp_start,
                "timestamp_end": timestamp_start + timedelta(milliseconds=source.duration_ms),
            }
        )
        envelopes.append({"flow": flow.model_dump(mode="json"), "signature": None})

    publish_batch_latencies_ms: list[float] = []
    started = perf_counter()
    for offset in range(0, total, publish_batch_size):
        payloads = envelopes[offset : offset + publish_batch_size]
        publish_started = perf_counter()
        bus.publish_batch(FLOW_STREAM, payloads)
        publish_batch_latencies_ms.append((perf_counter() - publish_started) * 1000)
    publish_elapsed = perf_counter() - started

    deadline = perf_counter() + timeout_seconds
    flow_count = 0
    detection_payloads: list[dict[str, object]] = []
    while perf_counter() < deadline:
        flow_count, detection_payloads = _persisted(repository, run_id)
        if flow_count == total and len(detection_payloads) == total:
            break
        sleep(0.05)
    elapsed = perf_counter() - started
    if flow_count != total or len(detection_payloads) != total:
        raise RuntimeError(
            "pipeline benchmark timed out "
            f"(flows={flow_count}/{total}, detections={len(detection_payloads)}/{total})"
        )

    inference_latencies = [
        cast(float, payload["inference_latency_ms"]) for payload in detection_payloads
    ]
    processing_latencies = [
        cast(float, payload["processing_latency_ms"]) for payload in detection_payloads
    ]
    return {
        "schema_version": "1.0.0",
        "generated_at": generated_at.isoformat(),
        "scope": "local Compose Redis-to-PostgreSQL exact pipeline benchmark",
        "generated_flows": total,
        "persisted_flows": flow_count,
        "persisted_detections": len(detection_payloads),
        "end_to_end_seconds": elapsed,
        "end_to_end_flows_per_second": total / elapsed,
        "ingress_publish": {
            "batch_size": publish_batch_size,
            "elapsed_seconds": publish_elapsed,
            "flows_per_second": total / publish_elapsed,
            "batch_latency_ms": {
                "p50": median(publish_batch_latencies_ms),
                "p95": _percentile(publish_batch_latencies_ms, 95),
                "p99": _percentile(publish_batch_latencies_ms, 99),
            },
        },
        "detector_inference_latency_ms": {
            "p50": median(inference_latencies),
            "p95": _percentile(inference_latencies, 95),
            "p99": _percentile(inference_latencies, 99),
        },
        "detector_processing_latency_ms": {
            "p50": median(processing_latencies),
            "p95": _percentile(processing_latencies, 95),
            "p99": _percentile(processing_latencies, 99),
        },
        "queue_after_completion": {
            "flows": bus.group_status(FLOW_STREAM, "detectors"),
            "detections": bus.group_status("aegisflow:detections", "api-core"),
        },
        "machine": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "processor": platform.processor(),
        },
        "limitations": [
            "Synthetic metadata-only fixtures measure mechanics, not detection accuracy.",
            "The result describes one local Compose host and is not a capacity guarantee.",
            "Database and Redis time are measured end to end, not isolated with server tracing.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark the local Redis/PostgreSQL pipeline")
    parser.add_argument("--total", type=int, default=2_000)
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    parser.add_argument("--publish-batch-size", type=int, default=64)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = run_pipeline_benchmark(
        total=args.total,
        redis_url=os.environ["AEGISFLOW_REDIS_URL"],
        database_url=os.environ["AEGISFLOW_DATABASE_URL"],
        timeout_seconds=args.timeout_seconds,
        publish_batch_size=args.publish_batch_size,
    )
    serialized = json.dumps(report, indent=2) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized, encoding="utf-8")
    print(serialized, end="")


if __name__ == "__main__":
    main()
