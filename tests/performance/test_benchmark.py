from __future__ import annotations

from datetime import UTC, datetime
from time import perf_counter

from sqlalchemy import insert

from apps.api.database import FlowRow, Repository, SensorRow
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


def test_dashboard_summaries_remain_bounded_with_large_ledger(tmp_path) -> None:
    repository = Repository(f"sqlite:///{(tmp_path / 'large-ledger.db').as_posix()}")
    repository.create_schema()
    rows = 100_000
    started = datetime(2026, 9, 10, tzinfo=UTC)
    with repository.engine.begin() as connection:
        connection.execute(
            insert(SensorRow),
            [{"id": "large-ledger", "last_seen": started, "mode": "live"}],
        )
        for offset in range(0, rows, 5_000):
            connection.execute(
                insert(FlowRow),
                [
                    {
                        "event_id": f"{index:036d}",
                        "sensor_id": "large-ledger",
                        "timestamp_start": started,
                        "timestamp_end": started,
                        "src_ip": f"10.0.{index % 250}.{index % 251}",
                        "dst_ip": f"192.0.2.{index % 251}",
                        "src_port": 40_000 + index % 20_000,
                        "dst_port": 443,
                        "protocol": "tcp",
                        "community_flow_id": f"1:large-{index}",
                        "payload": {},
                    }
                    for index in range(offset, min(offset + 5_000, rows))
                ],
            )

    query_started = perf_counter()
    status = repository.status()
    hosts = repository.hosts(limit=200)
    elapsed = perf_counter() - query_started

    assert status["flows"] == rows
    assert len(hosts) == 200
    assert all(host["flows"] > 0 for host in hosts)
    assert elapsed < 5.0
