import json

import pytest

from packages.contracts import Severity
from packages.detection.suricata import EveParseError, parse_eve_line


def test_suricata_alert_is_sanitized_and_normalized() -> None:
    line = json.dumps(
        {
            "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "alert",
            "flow_id": 123,
            "src_ip": "10.0.0.1",
            "dest_ip": "10.0.0.2",
            "payload_printable": "must not persist",
            "alert": {
                "signature_id": 9001,
                "signature": "Safe test signature",
                "category": "Test",
                "severity": 2,
            },
        }
    )
    event = parse_eve_line(line)
    assert event is not None
    assert event.severity == Severity.HIGH
    assert "payload" not in event.metadata
    assert len(event.raw_event_hash) == 64


def test_partial_eve_line_fails_visibly() -> None:
    with pytest.raises(EveParseError, match="malformed"):
        parse_eve_line('{"event_type":"alert"')


def test_non_alert_event_is_ignored() -> None:
    assert parse_eve_line('{"event_type":"dns"}') is None
