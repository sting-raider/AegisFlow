from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import event, func, select

from apps.api.database import IncidentAlertRow, IncidentRow, Repository
from packages.contracts import AnalystFeedback, FeedbackDisposition, Severity, Verdict
from packages.detection import DetectionEngine
from packages.incidents import DriftEvent, RuntimeDriftMonitor
from packages.model_bundle import ModelBundle
from scripts.generate_demo_pcaps import generate
from services.sensor import DemoAdapter, PcapAdapter


def test_demo_detection_persistence_and_idempotency(bundle: ModelBundle, tmp_path: Path) -> None:
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
    incident = repository.incidents()[0]
    context = repository.incident_explanation_context(incident["id"])
    assert context is not None
    serialized = str(context["payload"])
    assert incident["source_host"] not in serialized
    assert "src_ip" not in serialized
    assert "dst_ip" not in serialized
    assert context["payload"]["aggregated_features"]["flow_count"] >= 1


def test_repository_ingest_batch_commits_rows_and_reports_novelty(
    bundle: ModelBundle, tmp_path: Path
) -> None:
    repository = Repository(f"sqlite:///{(tmp_path / 'batch-ingest.db').as_posix()}")
    repository.create_schema()
    engine = DetectionEngine(bundle)
    flows = list(DemoAdapter().flows())[:3]
    detections = [engine.detect(flow) for flow in flows]

    outcomes = repository.ingest_batch(
        [(flow, detection, None) for flow, detection in zip(flows, detections, strict=True)]
    )
    duplicate = repository.ingest_batch([(flows[0], detections[0], None)])

    assert len(outcomes) == 3
    assert all(outcome.is_new_detection for outcome in outcomes)
    assert duplicate[0].is_new_detection is False
    assert repository.status()["flows"] == 3


def test_parent_rows_flush_before_foreign_key_dependants(
    bundle: ModelBundle, tmp_path: Path
) -> None:
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
    assert inserts.index("alerts") < inserts.index("incidents")
    assert inserts.index("incidents") < inserts.index("incident_alerts")


def test_incidents_group_on_explainable_rules_and_return_timeline(
    bundle: ModelBundle, tmp_path: Path
) -> None:
    repository = Repository(f"sqlite:///{(tmp_path / 'incidents.db').as_posix()}")
    repository.create_schema()
    base_flow = next(iter(DemoAdapter().flows()))
    base_detection = DetectionEngine(bundle).detect(base_flow)
    started = datetime(2026, 8, 1, tzinfo=UTC)
    scenarios = [
        ("10.0.0.1", "10.0.0.100", "PORT_SWEEP", 20.0, Severity.LOW),
        ("10.0.0.2", "10.0.0.100", "DESTINATION_FANOUT", 30.0, Severity.MEDIUM),
        ("10.0.0.3", "10.0.0.101", "DESTINATION_FANOUT", 40.0, Severity.HIGH),
        ("10.0.0.4", "10.0.0.102", "PORT_SWEEP", 50.0, Severity.HIGH),
        ("10.0.0.5", "10.0.0.103", "UNRELATED_SIGNAL", 60.0, Severity.CRITICAL),
    ]
    for index, (source, destination, reason, risk, severity) in enumerate(scenarios):
        flow = base_flow.model_copy(
            update={
                "event_id": uuid4(),
                "timestamp_start": started + timedelta(seconds=index),
                "timestamp_end": started + timedelta(seconds=index + 1),
                "src_ip": ip_address(source),
                "dst_ip": ip_address(destination),
                "community_flow_id": f"incident-flow-{index}",
            }
        )
        detection = base_detection.model_copy(
            update={
                "event_id": uuid4(),
                "flow_event_id": flow.event_id,
                "timestamp": flow.timestamp_end,
                "verdict": Verdict.SUSPICIOUS_UNKNOWN,
                "severity": severity,
                "reason_codes": [reason],
                "final_risk_score": risk,
            }
        )
        repository.ingest(flow, detection)

    incidents = repository.incidents()
    assert len(incidents) == 1
    summary = incidents[0]
    assert summary["alert_count"] == 5
    assert summary["title"] == "Correlated network activity"
    assert {
        "shared destination",
        "common reason",
        "similar attack stage (reconnaissance)",
        "repeated escalation",
        "time proximity",
    } <= set(summary["grouping_reasons"])
    assert summary["escalation_count"] >= 1
    assert summary["attack_stages"] == ["reconnaissance", "unclassified_anomaly"]

    detail = repository.incident(summary["id"])
    assert detail is not None
    assert len(detail["timeline"]) == 5
    assert len(detail["alerts"]) == 5
    assert detail["timeline"][0]["source_host"] == "10.0.0.1"
    assert detail["timeline"][-1]["severity"] == "critical"
    assert detail["destination_hosts"] == [
        "10.0.0.100",
        "10.0.0.101",
        "10.0.0.102",
        "10.0.0.103",
    ]
    with repository.session() as session:
        stored = session.get(IncidentRow, summary["id"])
        assert stored is not None
        assert stored.alert_ids == []
        assert stored.grouping_context is not None
        assert len(stored.grouping_context["recent_risks"]) <= 2
        membership_count = session.scalar(
            select(func.count(IncidentAlertRow.alert_id)).where(
                IncidentAlertRow.incident_id == summary["id"]
            )
        )
        assert membership_count == 5


def test_record_model_refreshes_loaded_manifest(tmp_path: Path) -> None:
    repository = Repository(f"sqlite:///{(tmp_path / 'models.db').as_posix()}")
    repository.create_schema()
    original = {"model_name": "smoke", "version": "1.0.0", "git_commit": "old"}
    refreshed = {**original, "git_commit": "current"}
    repository.record_model(original)
    repository.record_model(refreshed)
    models = repository.models()
    assert len(models) == 1
    assert models[0]["metadata"]["git_commit"] == "current"


def test_synthetic_pcap_replay_is_deterministic(tmp_path: Path) -> None:
    path = tmp_path / "demo.pcap"
    generate(path)
    first = list(PcapAdapter(path).flows())
    second = list(PcapAdapter(path).flows())
    assert len(first) == 2
    assert [flow.community_flow_id for flow in first] == [flow.community_flow_id for flow in second]
    assert all(flow.capture_mode.value == "pcap" for flow in first)


def test_pcap_identity_does_not_reverse_initiator_features(tmp_path: Path) -> None:
    from scapy.all import IP, TCP, Ether, wrpcap

    path = tmp_path / "direction.pcap"
    request = (
        Ether() / IP(src="203.0.113.9", dst="10.0.0.5") / TCP(sport=55_000, dport=443, flags="S")
    )
    response = (
        Ether() / IP(src="10.0.0.5", dst="203.0.113.9") / TCP(sport=443, dport=55_000, flags="SA")
    )
    request.time = 1_700_000_000.0
    response.time = 1_700_000_000.01
    wrpcap(str(path), [request, response])

    flow = next(iter(PcapAdapter(path).flows()))
    assert str(flow.src_ip) == "203.0.113.9"
    assert flow.src_port == 55_000
    assert str(flow.dst_ip) == "10.0.0.5"
    assert flow.dst_port == 443
    assert flow.packets_forward == flow.packets_reverse == 1
    assert flow.first_packet_directions == [1, -1]
    assert flow.protocol_metadata["direction_basis"] == "tcp_syn_without_ack"


def test_pcap_midstream_service_response_uses_port_direction_evidence(tmp_path: Path) -> None:
    from scapy.all import IP, UDP, Ether, wrpcap

    path = tmp_path / "midstream-direction.pcap"
    response = Ether() / IP(src="10.0.0.53", dst="203.0.113.9") / UDP(sport=53, dport=55_000)
    request = Ether() / IP(src="203.0.113.9", dst="10.0.0.53") / UDP(sport=55_000, dport=53)
    response.time = 1_700_000_000.0
    request.time = 1_700_000_000.01
    wrpcap(str(path), [response, request])

    flow = next(iter(PcapAdapter(path).flows()))

    assert str(flow.src_ip) == "203.0.113.9"
    assert flow.src_port == 55_000
    assert str(flow.dst_ip) == "10.0.0.53"
    assert flow.dst_port == 53
    assert flow.first_packet_directions == [-1, 1]
    assert flow.protocol_metadata["direction_basis"] == ("well_known_service_ephemeral_client")


def test_retention_cleanup_removes_expired_flow(bundle: ModelBundle, tmp_path: Path) -> None:
    repository = Repository(f"sqlite:///{(tmp_path / 'retention.db').as_posix()}")
    repository.create_schema()
    flow, detection = next(
        (candidate, result)
        for candidate in DemoAdapter().flows()
        if (result := DetectionEngine(bundle).detect(candidate)).verdict != Verdict.BENIGN
    )
    repository.ingest(flow, detection)
    alert = repository.alerts()[0]
    repository.add_feedback(
        AnalystFeedback(
            alert_id=UUID(alert["id"]),
            actor="retention-test",
            disposition=FeedbackDisposition.BENIGN_NEW_BEHAVIOUR,
            original_model_result=alert["detection"],
            model_version=alert["detection"]["classifier_model_version"],
            eligible_for_retraining=True,
        )
    )
    repository.record_health_event("test", "ok")
    counts = repository.cleanup_before(datetime(2027, 1, 1, tzinfo=UTC))
    assert counts["flows"] == 1
    assert counts["feedback"] == 1
    assert counts["incidents"] == 1
    assert counts["audit_events"] == 1
    assert counts["health_events"] == 1
    assert repository.status()["flows"] == 0
    assert repository.retraining_candidates() == []
    assert repository.health_events() == []


def test_runtime_drift_events_are_persisted_idempotently(
    bundle: ModelBundle, tmp_path: Path
) -> None:
    repository = Repository(f"sqlite:///{(tmp_path / 'drift.db').as_posix()}")
    repository.create_schema()
    monitor = RuntimeDriftMonitor("0.2.0", window_size=8)
    base_flow = next(iter(DemoAdapter().flows()))
    base_detection = DetectionEngine(bundle).detect(base_flow)
    events: list[DriftEvent] = []
    for index in range(16):
        shifted = index >= 8
        flow = base_flow.model_copy(update={"duration_ms": 80_000_000.0 if shifted else 100.0})
        detection = base_detection.model_copy(
            update={
                "event_id": uuid4(),
                "timestamp": datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=index),
                "anomaly_score": 0.9 if shifted else 0.1,
            }
        )
        events.extend(monitor.observe(flow, detection))
    event = next(item for item in events if item.signal == "anomaly_score")
    assert repository.record_drift_event(event)
    assert not repository.record_drift_event(event)
    persisted = repository.drift_events()
    assert persisted[0]["automatic_action_allowed"] is False
    assert persisted[0]["trigger_detection_id"] == str(event.trigger_detection_id)
