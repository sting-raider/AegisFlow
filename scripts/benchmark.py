from __future__ import annotations

import argparse
import json
import platform
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from queue import Empty, Full, Queue
from statistics import mean, median, quantiles
from threading import Thread
from time import perf_counter
from typing import cast

import psutil

from packages.contracts import FlowEvent
from packages.detection import DetectionEngine
from packages.model_bundle import BundleError, ModelBundle, load_production_bundle
from services.sensor import DemoAdapter
from training.cli.train_smoke import train


def percentile(values: list[float], index: int) -> float:
    if len(values) == 1:
        return values[0]
    return quantiles(values, n=100, method="inclusive")[index - 1]


def run_benchmark(
    bundle: ModelBundle,
    *,
    total: int = 2_000,
    queue_capacity: int = 256,
    batch_size: int = 64,
) -> dict[str, object]:
    if total < 2:
        raise ValueError("benchmark requires at least two generated flows")
    if queue_capacity < 1:
        raise ValueError("queue capacity must be positive")
    if batch_size < 1 or batch_size > 512:
        raise ValueError("batch size must be in [1, 512]")
    engine = DetectionEngine(bundle)
    fixtures = list(DemoAdapter().flows())
    queue: Queue[tuple[FlowEvent, float] | None] = Queue(maxsize=queue_capacity)
    inference_latencies: list[float] = []
    processing_latencies: list[float] = []
    process = psutil.Process()
    start_cpu = process.cpu_times()
    start_memory = process.memory_info().rss
    peak_memory = start_memory
    batch_sizes: list[int] = []
    stage_totals_ms: defaultdict[str, float] = defaultdict(float)

    def consume() -> None:
        nonlocal peak_memory
        while True:
            item = queue.get()
            if item is None:
                queue.task_done()
                return
            items = [item]
            stop_after_batch = False
            while len(items) < batch_size:
                try:
                    candidate = queue.get_nowait()
                except Empty:
                    break
                if candidate is None:
                    queue.task_done()
                    stop_after_batch = True
                    break
                items.append(candidate)

            flows = [flow for flow, _ in items]
            enqueued = [timestamp for _, timestamp in items]

            def observe(stage: str, duration_ms: float, _rows: int) -> None:
                stage_totals_ms[stage] += duration_ms

            results = engine.detect_batch(
                flows,
                processing_started=enqueued,
                stage_observer=observe,
            )
            serialization_started = perf_counter()
            for flow, result in zip(flows, results, strict=True):
                json.dumps(
                    {
                        "flow": flow.model_dump(mode="json"),
                        "signature": None,
                        "detection": result.model_dump(mode="json"),
                    },
                    separators=(",", ":"),
                )
            stage_totals_ms["serialization"] += (
                perf_counter() - serialization_started
            ) * 1000
            inference_latencies.extend(result.inference_latency_ms for result in results)
            processing_latencies.extend(result.processing_latency_ms for result in results)
            batch_sizes.append(len(items))
            peak_memory = max(peak_memory, process.memory_info().rss)
            for _ in items:
                queue.task_done()
            if stop_after_batch:
                return

    worker = Thread(target=consume, name="benchmark-detector", daemon=True)
    worker.start()
    dropped = 0
    maximum_queue_depth = 0
    started = perf_counter()
    for index in range(total):
        try:
            queue.put((fixtures[index % len(fixtures)], perf_counter()), timeout=0.001)
            maximum_queue_depth = max(maximum_queue_depth, queue.qsize())
        except Full:
            dropped += 1
    queue.put(None)
    queue.join()
    worker.join(timeout=5)
    elapsed = perf_counter() - started
    end_cpu = process.cpu_times()
    end_memory = process.memory_info().rss
    processed = len(inference_latencies)
    cpu_seconds = (end_cpu.user + end_cpu.system) - (start_cpu.user + start_cpu.system)
    observed_stage_ms = sum(stage_totals_ms.values())
    return {
        "scope": (
            "single-process bounded-queue synthetic burst benchmark with exact runtime "
            "hybrid batching"
        ),
        "generated_flows": total,
        "processed_flows": processed,
        "flows_per_second": processed / elapsed,
        "batching": {
            "configured_size": batch_size,
            "batches_processed": len(batch_sizes),
            "average_batch_fill": mean(batch_sizes),
            "maximum_batch_fill": max(batch_sizes),
        },
        "inference_latency_ms": {
            "p50": median(inference_latencies),
            "p95": percentile(inference_latencies, 95),
            "p99": percentile(inference_latencies, 99),
        },
        "processing_latency_ms": {
            "p50": median(processing_latencies),
            "p95": percentile(processing_latencies, 95),
            "p99": percentile(processing_latencies, 99),
        },
        "elapsed_seconds": elapsed,
        "queue": {
            "capacity": queue_capacity,
            "maximum_depth": maximum_queue_depth,
            "growth_from_empty": maximum_queue_depth,
            "final_depth": queue.qsize(),
        },
        "dropped_events": dropped,
        "stage_profile": {
            stage: {
                "total_ms": duration,
                "per_processed_flow_ms": duration / processed,
                "observed_stage_share": (
                    duration / observed_stage_ms if observed_stage_ms else 0.0
                ),
            }
            for stage, duration in sorted(stage_totals_ms.items())
        },
        "resource_usage": {
            "cpu_seconds": cpu_seconds,
            "average_process_cpu_percent": cpu_seconds / elapsed * 100,
            "rss_start_bytes": start_memory,
            "rss_peak_bytes": peak_memory,
            "rss_end_bytes": end_memory,
        },
        "machine": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "processor": platform.processor(),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark the exact hybrid detector path")
    parser.add_argument("--total", type=int, default=2_000)
    parser.add_argument("--queue-capacity", type=int, default=2_000)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--output", type=Path, default=Path("docs/BENCHMARK_LATEST.json"))
    parser.add_argument("--versioned-output", type=Path)
    args = parser.parse_args()
    registry = Path("models/registry")
    try:
        bundle = load_production_bundle(registry)
    except BundleError:
        train(registry)
        bundle = load_production_bundle(registry)
    baseline = run_benchmark(
        bundle,
        total=args.total,
        queue_capacity=args.queue_capacity,
        batch_size=1,
    )
    batched = run_benchmark(
        bundle,
        total=args.total,
        queue_capacity=args.queue_capacity,
        batch_size=args.batch_size,
    )
    baseline_rate = cast(float, baseline["flows_per_second"])
    batched_rate = cast(float, batched["flows_per_second"])
    report = {
        "schema_version": "2.0.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "model_version": bundle.version,
        "workload": {
            "generated_flows_per_run": args.total,
            "source": "repeated deterministic demo flow fixtures",
            "queue_capacity": args.queue_capacity,
        },
        "single_flow_baseline": baseline,
        "batched_runtime": batched,
        "throughput_speedup": batched_rate / baseline_rate,
        "limitations": [
            "Synthetic fixture repetition measures detector mechanics, not attack accuracy.",
            "This local benchmark excludes Redis network I/O and database persistence.",
            "Capacity varies by CPU, model bundle, traffic mix, and batch fill.",
        ],
    }
    serialized = json.dumps(report, indent=2) + "\n"
    outputs = [args.output]
    if args.versioned_output is not None:
        outputs.append(args.versioned_output)
    for output in outputs:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(serialized, encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
