from __future__ import annotations

import json
import platform
from pathlib import Path
from statistics import quantiles
from time import perf_counter

from packages.detection import DetectionEngine
from packages.model_bundle import BundleError, load_production_bundle
from services.sensor import DemoAdapter
from training.cli.train_smoke import train


def percentile(values: list[float], index: int) -> float:
    return quantiles(values, n=100, method="inclusive")[index - 1]


def main() -> None:
    registry = Path("models/registry")
    try:
        bundle = load_production_bundle(registry)
    except BundleError:
        train(registry)
        bundle = load_production_bundle(registry)
    engine = DetectionEngine(bundle)
    flows = list(DemoAdapter().flows())
    latencies: list[float] = []
    total = 2_000
    started = perf_counter()
    for index in range(total):
        result = engine.detect(flows[index % len(flows)])
        latencies.append(result.inference_latency_ms)
    elapsed = perf_counter() - started
    report = {
        "scope": "single-process synthetic inference benchmark",
        "flows": total,
        "flows_per_second": total / elapsed,
        "latency_ms": {
            "p50": percentile(latencies, 50),
            "p95": percentile(latencies, 95),
            "p99": percentile(latencies, 99),
        },
        "elapsed_seconds": elapsed,
        "machine": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "processor": platform.processor(),
        },
        "queue_growth": "not measured by single-process benchmark",
        "dropped_events": 0,
    }
    Path("docs").mkdir(exist_ok=True)
    Path("docs/BENCHMARK_LATEST.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
