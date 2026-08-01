from __future__ import annotations

import json
import platform
from pathlib import Path
from queue import Full, Queue
from statistics import median, quantiles
from threading import Thread
from time import perf_counter

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
    bundle: ModelBundle, *, total: int = 2_000, queue_capacity: int = 256
) -> dict[str, object]:
    if total < 2:
        raise ValueError("benchmark requires at least two generated flows")
    if queue_capacity < 1:
        raise ValueError("queue capacity must be positive")
    engine = DetectionEngine(bundle)
    fixtures = list(DemoAdapter().flows())
    queue: Queue[tuple[FlowEvent, float] | None] = Queue(maxsize=queue_capacity)
    inference_latencies: list[float] = []
    processing_latencies: list[float] = []
    process = psutil.Process()
    start_cpu = process.cpu_times()
    start_memory = process.memory_info().rss
    peak_memory = start_memory

    def consume() -> None:
        nonlocal peak_memory
        while True:
            item = queue.get()
            if item is None:
                queue.task_done()
                return
            flow, enqueued_at = item
            result = engine.detect(flow)
            inference_latencies.append(result.inference_latency_ms)
            processing_latencies.append((perf_counter() - enqueued_at) * 1000)
            peak_memory = max(peak_memory, process.memory_info().rss)
            queue.task_done()

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
    return {
        "scope": "single-process bounded-queue synthetic burst benchmark",
        "generated_flows": total,
        "processed_flows": processed,
        "flows_per_second": processed / elapsed,
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
    registry = Path("models/registry")
    try:
        bundle = load_production_bundle(registry)
    except BundleError:
        train(registry)
        bundle = load_production_bundle(registry)
    report = run_benchmark(bundle)
    Path("docs").mkdir(exist_ok=True)
    Path("docs/BENCHMARK_LATEST.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
