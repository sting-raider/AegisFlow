from packages.incidents.drift import WindowDriftDetector
from packages.incidents.explanations import TemplateExplanationProvider, sanitize_explanation_input


def test_drift_event_created_once_for_mean_shift() -> None:
    detector = WindowDriftDetector("anomaly_score", "0.1.0", window_size=8, threshold=0.3)
    events = [detector.update(value) for value in [0.1] * 8 + [0.8] * 8]
    assert sum(event is not None for event in events) == 1
    event = next(event for event in events if event)
    assert event is not None
    assert event.recommended_action.startswith("Review")


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
