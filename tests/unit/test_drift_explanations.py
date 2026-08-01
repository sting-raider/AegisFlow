from datetime import UTC, datetime, timedelta
from uuid import uuid4

from packages.contracts import Verdict
from packages.detection import DetectionEngine
from packages.incidents.drift import DriftEvent, RuntimeDriftMonitor, WindowDriftDetector
from packages.incidents.explanations import TemplateExplanationProvider, sanitize_explanation_input
from packages.model_bundle import ModelBundle
from services.sensor import DemoAdapter


def test_drift_event_created_once_for_mean_shift() -> None:
    detector = WindowDriftDetector("anomaly_score", "0.1.0", window_size=8, threshold=0.3)
    events = [detector.update(value) for value in [0.1] * 8 + [0.8] * 8]
    assert sum(event is not None for event in events) == 1
    event = next(event for event in events if event)
    assert event is not None
    assert event.recommended_action.startswith("Review")
    assert event.reference_mean == 0.1
    assert event.recent_mean == 0.8


def test_runtime_monitor_covers_required_signals_without_automatic_action(
    bundle: ModelBundle,
) -> None:
    monitor = RuntimeDriftMonitor("0.2.0", window_size=8)
    original_flow = next(iter(DemoAdapter().flows()))
    original_detection = DetectionEngine(bundle).detect(original_flow)
    started = datetime(2026, 1, 1, tzinfo=UTC)
    events: list[DriftEvent] = []
    for index in range(16):
        shifted = index >= 8
        flow = original_flow.model_copy(
            update={
                "duration_ms": 80_000_000.0 if shifted else 100.0,
                "bytes_forward": 900_000_000_000_000 if shifted else 100,
                "bytes_reverse": 100,
                "packet_length_mean": 60_000.0 if shifted else 100.0,
            }
        )
        detection = original_detection.model_copy(
            update={
                "event_id": uuid4(),
                "timestamp": started + timedelta(seconds=index),
                "anomaly_score": 0.9 if shifted else 0.1,
                "classifier_confidence": 0.2 if shifted else 0.9,
                "verdict": Verdict.SUSPICIOUS_UNKNOWN if shifted else Verdict.BENIGN,
            }
        )
        events.extend(monitor.observe(flow, detection))
        assert monitor.observe(flow, detection) == ()
    signals = {event.signal for event in events}
    assert "flow_rate" in monitor.detectors
    assert {
        "anomaly_score",
        "known_class_confidence",
        "feature_duration",
        "feature_bytes_total",
        "feature_packet_length_mean",
        "alert_rate",
    } <= signals
    assert all(not event.automatic_action_allowed for event in events)
    assert all(not event.eligible_for_retraining for event in events)


def test_explanation_sanitizer_drops_ips_payload_and_secrets() -> None:
    sanitized = sanitize_explanation_input(
        {
            "verdict": "suspicious_unknown",
            "reason_codes": ["ISOLATION_OUTLIER"],
            "src_ip": "10.0.0.1",
            "payload": "secret",
            "api_key": "secret",
        }
    )
    assert "src_ip" not in sanitized
    assert "payload" not in sanitized
    assert "api_key" not in sanitized
    text = TemplateExplanationProvider().explain(sanitized)
    assert "not proof" in text
