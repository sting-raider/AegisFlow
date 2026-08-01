from __future__ import annotations

from packages.model_bundle import ModelBundle
from scripts.benchmark import run_benchmark


def test_bounded_queue_benchmark_reports_conservation_and_resources(
    bundle: ModelBundle,
) -> None:
    report = run_benchmark(bundle, total=100, queue_capacity=16)
    processed = int(report["processed_flows"])
    dropped = int(report["dropped_events"])
    queue = report["queue"]
    resources = report["resource_usage"]

    assert processed + dropped == 100
    assert processed > 0
    assert isinstance(queue, dict)
    assert queue["maximum_depth"] <= queue["capacity"] == 16
    assert queue["final_depth"] == 0
    assert isinstance(resources, dict)
    assert resources["cpu_seconds"] >= 0
    assert resources["rss_peak_bytes"] >= resources["rss_start_bytes"]
    assert set(report["processing_latency_ms"]) == {"p50", "p95", "p99"}
