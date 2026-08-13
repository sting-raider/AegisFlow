from __future__ import annotations

import argparse
import json
import math
import os
import platform
from datetime import UTC, datetime, timedelta
from pathlib import Path
from statistics import median, quantiles
from time import perf_counter, sleep
from typing import TypedDict
from uuid import NAMESPACE_URL, uuid4, uuid5

import numpy as np
import psutil
from sqlalchemy import select

from apps.api.database import DetectionRow, FlowRow, Repository
from packages.common.bus import RedisStreamBus
from scripts.benchmark_pipeline import (
    ALLOWED_BENCHMARK_HOSTS,
    FLOW_STREAM,
    _persisted,
    _require_local_service_url,
)
from services.sensor import DemoAdapter

DETECTION_STREAM = "aegisflow:detections"


class SustainabilityCriteria(TypedDict):
    input_rate_maintained: bool
    queue_depth_bounded: bool
    no_unexplained_loss: bool
    latency_sample_complete: bool
    latency_within_budget: bool
    returned_to_steady_state: bool


class SustainabilityAssessment(TypedDict):
    sustainable: bool
    criteria: SustainabilityCriteria
    failures: list[str]


def _percentile(values: list[float], index: int) -> float | None:
    if not values:
        return None
    if len(values) == 1:
        return values[0]
    return quantiles(values, n=100, method="inclusive")[index - 1]


def queue_growth_per_second(samples: list[dict[str, float]], field: str) -> float:
    """Return least-squares queue growth over the second half of paced ingress."""
    if len(samples) < 4:
        return 0.0
    selected = samples[len(samples) // 2 :]
    times = np.asarray([item["elapsed_seconds"] for item in selected], dtype=np.float64)
    depths = np.asarray([item[field] for item in selected], dtype=np.float64)
    if float(np.ptp(times)) < 1e-9:
        return 0.0
    centered = times - float(np.mean(times))
    denominator = float(np.sum(centered**2))
    if denominator < 1e-12:
        return 0.0
    return float(np.sum(centered * (depths - float(np.mean(depths)))) / denominator)


def assess_sustainability(
    *,
    planned: int,
    published: int,
    persisted_flows: int,
    persisted_detections: int,
    durable_latency_samples: int,
    achieved_rate: float,
    target_rate: float,
    latency_p95_ms: float | None,
    latency_budget_ms: float,
    final_flow_depth: int,
    final_detection_depth: int,
    maximum_flow_depth: int,
    maximum_detection_depth: int,
    queue_depth_budget: int,
    flow_growth_per_second: float,
    detection_growth_per_second: float,
    growth_tolerance_per_second: float,
) -> SustainabilityAssessment:
    failures: list[str] = []
    if published != planned:
        failures.append(f"published {published}/{planned} planned flows")
    if persisted_flows != published or persisted_detections != published:
        failures.append(
            "durability mismatch "
            f"(flows={persisted_flows}, detections={persisted_detections}, "
            f"published={published})"
        )
    if durable_latency_samples != published:
        failures.append(
            "durable latency sample mismatch "
            f"(samples={durable_latency_samples}, published={published})"
        )
    minimum_rate = target_rate * 0.98
    if achieved_rate < minimum_rate:
        failures.append(
            f"paced ingress achieved {achieved_rate:.2f} < {minimum_rate:.2f} flows/s"
        )
    if latency_p95_ms is None or latency_p95_ms > latency_budget_ms:
        rendered = "unavailable" if latency_p95_ms is None else f"{latency_p95_ms:.2f}"
        failures.append(
            f"durable latency p95 {rendered} ms exceeds {latency_budget_ms:.2f} ms"
        )
    if final_flow_depth or final_detection_depth:
        failures.append(
            "pipeline did not return to steady state "
            f"(flow_depth={final_flow_depth}, detection_depth={final_detection_depth})"
        )
    if maximum_flow_depth > queue_depth_budget:
        failures.append(
            f"flow queue depth {maximum_flow_depth} exceeds budget {queue_depth_budget}"
        )
    if maximum_detection_depth > queue_depth_budget:
        failures.append(
            "detection queue depth "
            f"{maximum_detection_depth} exceeds budget {queue_depth_budget}"
        )
    if flow_growth_per_second > growth_tolerance_per_second:
        failures.append(
            "flow queue grows "
            f"{flow_growth_per_second:.3f} messages/s above tolerance "
            f"{growth_tolerance_per_second:.3f}"
        )
    if detection_growth_per_second > growth_tolerance_per_second:
        failures.append(
            "detection queue grows "
            f"{detection_growth_per_second:.3f} messages/s above tolerance "
            f"{growth_tolerance_per_second:.3f}"
        )
    return {
        "sustainable": not failures,
        "criteria": {
            "input_rate_maintained": achieved_rate >= minimum_rate,
            "queue_depth_bounded": (
                maximum_flow_depth <= queue_depth_budget
                and maximum_detection_depth <= queue_depth_budget
                and flow_growth_per_second <= growth_tolerance_per_second
                and detection_growth_per_second <= growth_tolerance_per_second
            ),
            "no_unexplained_loss": (
                published == planned
                and persisted_flows == published
                and persisted_detections == published
            ),
            "latency_sample_complete": durable_latency_samples == published,
            "latency_within_budget": (
                latency_p95_ms is not None and latency_p95_ms <= latency_budget_ms
            ),
            "returned_to_steady_state": (
                final_flow_depth == 0 and final_detection_depth == 0
            ),
        },
        "failures": failures,
    }


def _new_durable_latencies(
    repository: Repository,
    sensor_id: str,
    after: datetime | None,
    observed_at: datetime,
    seen_event_ids: set[object],
) -> tuple[datetime | None, list[float]]:
    with repository.session() as session:
        statement = (
            select(FlowRow.event_id, FlowRow.timestamp_start)
            .join(DetectionRow, DetectionRow.flow_event_id == FlowRow.event_id)
            .where(FlowRow.sensor_id == sensor_id)
            .order_by(FlowRow.timestamp_start.asc())
        )
        if after is not None:
            statement = statement.where(FlowRow.timestamp_start > after)
        rows = list(session.execute(statement))
    if not rows:
        return after, []
    normalized = []
    for event_id, value in rows:
        if event_id in seen_event_ids:
            continue
        seen_event_ids.add(event_id)
        normalized.append(
            value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
        )
    newest = rows[-1][1]
    newest = newest.replace(tzinfo=UTC) if newest.tzinfo is None else newest.astimezone(UTC)
    latencies = [
        max(0.0, (observed_at - timestamp).total_seconds() * 1000.0)
        for timestamp in normalized
    ]
    return newest, latencies


def run_sustained_benchmark(
    *,
    duration_seconds: float,
    target_rate: float,
    redis_url: str,
    database_url: str,
    publish_batch_size: int = 25,
    sample_interval_seconds: float = 1.0,
    drain_timeout_seconds: float = 180.0,
    p95_latency_budget_ms: float = 5_000.0,
    queue_depth_budget: int = 10_000,
) -> dict[str, object]:
    if duration_seconds < 10:
        raise ValueError("sustained benchmark duration must be at least 10 seconds")
    if not math.isfinite(target_rate) or target_rate <= 0:
        raise ValueError("target rate must be finite and positive")
    if not 1 <= publish_batch_size <= 512:
        raise ValueError("publish batch size must be in [1, 512]")
    if not 0.1 <= sample_interval_seconds <= 30:
        raise ValueError("sample interval must be in [0.1, 30] seconds")
    if drain_timeout_seconds <= 0:
        raise ValueError("drain timeout must be positive")
    if p95_latency_budget_ms <= 0 or queue_depth_budget < 1:
        raise ValueError("latency and queue budgets must be positive")
    redis_url = _require_local_service_url(redis_url, "Redis URL")
    database_url = _require_local_service_url(database_url, "database URL")
    bus = RedisStreamBus(redis_url)
    repository = Repository(database_url)
    if not bus.ping():
        raise RuntimeError("Redis is not ready")
    fixtures = list(DemoAdapter().flows())
    planned = int(duration_seconds * target_rate)
    if planned < 2:
        raise ValueError("sustained benchmark requires at least two flows")
    run_id = f"sustained-{uuid4().hex[:12]}"
    generated_at = datetime.now(UTC)
    started = perf_counter()
    next_sample_at = started
    published = 0
    publish_latencies_ms: list[float] = []
    durable_latencies_ms: list[float] = []
    seen_durable_event_ids: set[object] = set()
    last_durable_timestamp: datetime | None = None
    samples: list[dict[str, float]] = []
    cpu_samples: list[float] = []
    memory_samples: list[float] = []
    psutil.cpu_percent(interval=None)

    def sample(*, publishing: bool) -> tuple[int, int]:
        nonlocal last_durable_timestamp
        now = perf_counter()
        observed_at = datetime.now(UTC)
        flow_status = bus.group_status(FLOW_STREAM, "detectors")
        detection_status = bus.group_status(DETECTION_STREAM, "api-core")
        last_durable_timestamp, new_latencies = _new_durable_latencies(
            repository,
            run_id,
            last_durable_timestamp,
            observed_at,
            seen_durable_event_ids,
        )
        durable_latencies_ms.extend(new_latencies)
        flow_depth = flow_status["pending"] + flow_status["lag"]
        detection_depth = detection_status["pending"] + detection_status["lag"]
        cpu = float(psutil.cpu_percent(interval=None))
        memory = float(psutil.virtual_memory().percent)
        cpu_samples.append(cpu)
        memory_samples.append(memory)
        samples.append(
            {
                "elapsed_seconds": now - started,
                "published": float(published),
                "durable": float(len(durable_latencies_ms)),
                "flow_queue_depth": float(flow_depth),
                "detection_queue_depth": float(detection_depth),
                "host_cpu_percent": cpu,
                "host_memory_percent": memory,
                "publishing": float(publishing),
            }
        )
        return flow_depth, detection_depth

    while published < planned:
        scheduled = started + published / target_rate
        remaining = scheduled - perf_counter()
        if remaining > 0:
            sleep(remaining)
        count = min(publish_batch_size, planned - published)
        timestamp = datetime.now(UTC)
        envelopes: list[dict[str, object]] = []
        for offset in range(count):
            index = published + offset
            source = fixtures[index % len(fixtures)]
            timestamp_start = timestamp + timedelta(microseconds=offset)
            flow = source.model_copy(
                update={
                    "event_id": uuid5(
                        NAMESPACE_URL,
                        f"aegisflow-sustained-benchmark:{run_id}:{index}",
                    ),
                    "sensor_id": run_id,
                    "timestamp_start": timestamp_start,
                    "timestamp_end": timestamp_start
                    + timedelta(milliseconds=source.duration_ms),
                }
            )
            envelopes.append({"flow": flow.model_dump(mode="json"), "signature": None})
        publish_started = perf_counter()
        bus.publish_batch(FLOW_STREAM, envelopes)
        publish_latencies_ms.append((perf_counter() - publish_started) * 1000.0)
        published += count
        if perf_counter() >= next_sample_at:
            sample(publishing=True)
            next_sample_at = perf_counter() + sample_interval_seconds

    target_end = started + duration_seconds
    if perf_counter() < target_end:
        sleep(target_end - perf_counter())
    publish_elapsed = perf_counter() - started
    sample(publishing=True)
    publish_samples = list(samples)

    drain_started = perf_counter()
    final_flow_depth = -1
    final_detection_depth = -1
    persisted_flows = 0
    persisted_detections = 0
    while perf_counter() - drain_started <= drain_timeout_seconds:
        final_flow_depth, final_detection_depth = sample(publishing=False)
        persisted_flows, detection_payloads = _persisted(repository, run_id)
        persisted_detections = len(detection_payloads)
        if (
            persisted_flows == published
            and persisted_detections == published
            and final_flow_depth == 0
            and final_detection_depth == 0
        ):
            break
        sleep(min(0.5, sample_interval_seconds))
    completed_at = datetime.now(UTC)
    _, reconciled_latencies = _new_durable_latencies(
        repository,
        run_id,
        None,
        completed_at,
        seen_durable_event_ids,
    )
    durable_latencies_ms.extend(reconciled_latencies)
    total_elapsed = perf_counter() - started
    flow_growth = queue_growth_per_second(publish_samples, "flow_queue_depth")
    detection_growth = queue_growth_per_second(
        publish_samples, "detection_queue_depth"
    )
    maximum_flow_depth = int(max(item["flow_queue_depth"] for item in samples))
    maximum_detection_depth = int(
        max(item["detection_queue_depth"] for item in samples)
    )
    p95_latency = _percentile(durable_latencies_ms, 95)
    achieved_rate = published / publish_elapsed
    growth_tolerance = max(0.1, target_rate * 0.02)
    verdict = assess_sustainability(
        planned=planned,
        published=published,
        persisted_flows=persisted_flows,
        persisted_detections=persisted_detections,
        durable_latency_samples=len(durable_latencies_ms),
        achieved_rate=achieved_rate,
        target_rate=target_rate,
        latency_p95_ms=p95_latency,
        latency_budget_ms=p95_latency_budget_ms,
        final_flow_depth=final_flow_depth,
        final_detection_depth=final_detection_depth,
        maximum_flow_depth=maximum_flow_depth,
        maximum_detection_depth=maximum_detection_depth,
        queue_depth_budget=queue_depth_budget,
        flow_growth_per_second=flow_growth,
        detection_growth_per_second=detection_growth,
        growth_tolerance_per_second=growth_tolerance,
    )
    return {
        "schema_version": "1.0.0",
        "generated_at": generated_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "scope": "paced local Compose Redis-to-PostgreSQL sustained benchmark",
        "safety": {
            "allowed_hosts": sorted(ALLOWED_BENCHMARK_HOSTS),
            "payloads_stored": False,
            "external_targets": False,
        },
        "configuration": {
            "duration_seconds": duration_seconds,
            "target_flows_per_second": target_rate,
            "publish_batch_size": publish_batch_size,
            "sample_interval_seconds": sample_interval_seconds,
            "drain_timeout_seconds": drain_timeout_seconds,
            "p95_latency_budget_ms": p95_latency_budget_ms,
            "queue_depth_budget": queue_depth_budget,
            "queue_growth_tolerance_per_second": growth_tolerance,
        },
        "counts": {
            "planned": planned,
            "published": published,
            "persisted_flows": persisted_flows,
            "persisted_detections": persisted_detections,
            "durable_latency_samples": len(durable_latencies_ms),
        },
        "timing": {
            "paced_publish_seconds": publish_elapsed,
            "total_with_drain_seconds": total_elapsed,
            "achieved_publish_rate": achieved_rate,
            "end_to_end_durable_rate": published / max(total_elapsed, 1e-12),
            "drain_seconds": total_elapsed - publish_elapsed,
        },
        "latency_ms": {
            "durable_p50": _percentile(durable_latencies_ms, 50),
            "durable_p95": p95_latency,
            "durable_p99": _percentile(durable_latencies_ms, 99),
            "publish_batch_p50": median(publish_latencies_ms),
            "publish_batch_p95": _percentile(publish_latencies_ms, 95),
            "publish_batch_p99": _percentile(publish_latencies_ms, 99),
        },
        "queues": {
            "maximum_flow_depth": maximum_flow_depth,
            "maximum_detection_depth": maximum_detection_depth,
            "final_flow_depth": final_flow_depth,
            "final_detection_depth": final_detection_depth,
            "flow_growth_per_second": flow_growth,
            "detection_growth_per_second": detection_growth,
        },
        "resources": {
            "host_cpu_percent_p50": _percentile(cpu_samples, 50),
            "host_cpu_percent_p95": _percentile(cpu_samples, 95),
            "host_memory_percent_p50": _percentile(memory_samples, 50),
            "host_memory_percent_p95": _percentile(memory_samples, 95),
        },
        "samples": samples,
        "verdict": verdict,
        "machine": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "processor": platform.processor(),
            "logical_cpu_count": psutil.cpu_count(),
            "memory_bytes": psutil.virtual_memory().total,
        },
        "limitations": [
            "Synthetic metadata-only demo flows measure mechanics, not detection quality.",
            "Durable latency is observed by polling committed flow/detection joins and "
            "therefore includes up to one sample interval of measurement delay.",
            "Host CPU and memory percentages include unrelated local processes.",
            "The result describes one local Compose host and is not a capacity promise.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run a paced sustained local AegisFlow pipeline benchmark"
    )
    parser.add_argument("--duration-seconds", type=float, required=True)
    parser.add_argument("--target-rate", type=float, required=True)
    parser.add_argument("--publish-batch-size", type=int, default=25)
    parser.add_argument("--sample-interval-seconds", type=float, default=1.0)
    parser.add_argument("--drain-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--p95-latency-budget-ms", type=float, default=5_000.0)
    parser.add_argument("--queue-depth-budget", type=int, default=10_000)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run_sustained_benchmark(
        duration_seconds=args.duration_seconds,
        target_rate=args.target_rate,
        redis_url=os.environ["AEGISFLOW_REDIS_URL"],
        database_url=os.environ["AEGISFLOW_DATABASE_URL"],
        publish_batch_size=args.publish_batch_size,
        sample_interval_seconds=args.sample_interval_seconds,
        drain_timeout_seconds=args.drain_timeout_seconds,
        p95_latency_budget_ms=args.p95_latency_budget_ms,
        queue_depth_budget=args.queue_depth_budget,
    )
    serialized = json.dumps(report, indent=2) + "\n"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(serialized, encoding="utf-8")
    print(serialized, end="")
    if not report["verdict"]["sustainable"]:  # type: ignore[index]
        raise SystemExit(2)


if __name__ == "__main__":
    main()
