from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import event

from apps.api.database import Repository
from packages.detection import DetectionEngine
from scripts.generate_demo_pcaps import generate
from services.sensor import DemoAdapter, PcapAdapter


def test_demo_detection_persistence_and_idempotency(bundle, tmp_path: Path) -> None:
    repository = Repository(f"sqlite:///{(tmp_path / 'pipeline.db').as_posix()}")
    repository.create_schema()
    engine = DetectionEngine(bundle)
    flows = list(DemoAdapter().flows())
    detections = [engine.detect(flow) for flow in flows]
    for flow, detection in zip(flows, detections, strict=True):
        repository.ingest(flow, detection)
        repository.ingest(flow, detection)
    assert repository.status()["flows"] == len(flows)
    assert {result.verdict.value for result in detections} >= {
        "benign",
        "suspicious_unknown",
    }


def test_parent_rows_flush_before_foreign_key_dependants(bundle, tmp_path: Path) -> None:
    repository = Repository(f"sqlite:///{(tmp_path / 'flush-order.db').as_posix()}")
    repository.create_schema()
    statements: list[str] = []

    def capture_statement(
        _connection: Any,
        _cursor: Any,
        statement: str,
        _parameters: Any,
        _context: Any,
        _executemany: bool,
    ) -> None:
        if statement.lstrip().upper().startswith("INSERT"):
            statements.append(statement)

    event.listen(repository.engine, "before_cursor_execute", capture_statement)
    flow, detection = next(
        (flow, result)
        for flow in DemoAdapter().flows()
        if (result := DetectionEngine(bundle).detect(flow)).verdict.value != "benign"
    )
    repository.ingest(flow, detection)
    inserts = " ".join(statements)
    assert inserts.index("sensors") < inserts.index("flows")
    assert inserts.index("flows") < inserts.index("detection_results")
    assert inserts.index("detection_results") < inserts.index("alerts")


def test_synthetic_pcap_replay_is_deterministic(tmp_path: Path) -> None:
    path = tmp_path / "demo.pcap"
    generate(path)
    first = list(PcapAdapter(path).flows())
    second = list(PcapAdapter(path).flows())
    assert len(first) == 2
    assert [flow.community_flow_id for flow in first] == [flow.community_flow_id for flow in second]
    assert all(flow.capture_mode.value == "pcap" for flow in first)


def test_retention_cleanup_removes_expired_flow(bundle, tmp_path: Path) -> None:
    repository = Repository(f"sqlite:///{(tmp_path / 'retention.db').as_posix()}")
    repository.create_schema()
    flow = next(iter(DemoAdapter().flows()))
    detection = DetectionEngine(bundle).detect(flow)
    repository.ingest(flow, detection)
    counts = repository.cleanup_before(datetime(2027, 1, 1, tzinfo=UTC))
    assert counts["flows"] == 1
    assert repository.status()["flows"] == 0
