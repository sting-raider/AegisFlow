from __future__ import annotations

import json
from pathlib import Path

import pytest

from packages.contracts import Severity, SignatureEvent
from packages.detection.suricata import (
    EveJsonReader,
    EveMetadataEvent,
    EveParseError,
    correlate_eve_event,
    orient_flow_with_suricata,
    parse_eve_line,
)
from services.sensor import DemoAdapter


def _alert(**overrides: object) -> str:
    event: dict[str, object] = {
        "timestamp": "2026-01-01T00:00:00Z",
        "event_type": "alert",
        "flow_id": 123,
        "src_ip": "10.0.0.1",
        "src_port": 50_000,
        "dest_ip": "10.0.0.2",
        "dest_port": 443,
        "proto": "TCP",
        "payload_printable": "must not persist",
        "alert": {
            "signature_id": 9001,
            "signature": "Safe test signature",
            "category": "Test",
            "severity": 2,
        },
    }
    event.update(overrides)
    return json.dumps(event)


def test_suricata_alert_is_sanitized_normalized_and_deterministic() -> None:
    line = _alert()
    first = parse_eve_line(line)
    second = parse_eve_line(line)
    assert isinstance(first, SignatureEvent)
    assert isinstance(second, SignatureEvent)
    assert first.event_id == second.event_id
    assert first.severity == Severity.HIGH
    assert "payload" not in first.metadata
    assert len(first.raw_event_hash) == 64
    assert first.community_flow_id == "1:B4H0bMN0Rih3qr9C82AA7esBYLM="


def test_invalid_explicit_community_id_fails_visibly() -> None:
    with pytest.raises(EveParseError, match="incomplete"):
        parse_eve_line(_alert(community_id="1:fixture"))


def test_partial_eve_line_fails_visibly() -> None:
    with pytest.raises(EveParseError, match="malformed"):
        parse_eve_line('{"event_type":"alert"')


def test_dns_metadata_is_allow_listed_and_private_name_is_hashed() -> None:
    line = json.dumps(
        {
            "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "dns",
            "flow_id": 44,
            "src_ip": "10.0.0.1",
            "src_port": 53_000,
            "dest_ip": "10.0.0.2",
            "dest_port": 53,
            "proto": "UDP",
            "dns": {
                "type": "request",
                "queries": [{"rrname": "private.invalid", "rrtype": "A"}],
            },
        }
    )
    event = parse_eve_line(line)
    assert isinstance(event, EveMetadataEvent)
    assert event.event_type == "dns"
    assert event.metadata["dns_rrtype"] == "A"
    assert "dns_rrname_sha256" in event.metadata
    assert "private.invalid" not in event.metadata.values()


def test_fixture_covers_every_supported_eve_type() -> None:
    fixture = Path("tests/fixtures/suricata.eve.json")
    events = [parse_eve_line(line) for line in fixture.read_bytes().splitlines()]
    assert len(events) == 6
    assert isinstance(events[0], SignatureEvent)
    assert {event.event_type for event in events[1:] if isinstance(event, EveMetadataEvent)} == {
        "anomaly",
        "flow",
        "dns",
        "tls",
        "http",
    }


def test_incremental_reader_retains_partial_lines_and_deduplicates() -> None:
    raw = _alert().encode()
    reader = EveJsonReader()
    first = reader.feed(raw[:20])
    assert not first.events and not first.errors
    completed = reader.feed(raw[20:] + b"\n")
    assert len(completed.events) == 1
    duplicate = reader.feed(raw + b"\n")
    assert duplicate.duplicates == 1
    malformed = reader.feed(b'{"event_type":"alert"', final=True)
    assert len(malformed.errors) == 1
    assert reader.health.parsed_events == 1
    assert reader.health.duplicate_events == 1
    assert reader.health.malformed_events == 1


def test_correlation_prefers_flow_id_then_uses_tuple_and_time() -> None:
    flow = next(iter(DemoAdapter().flows()))
    exact = parse_eve_line(
        _alert(timestamp=flow.timestamp_start.isoformat(), community_id=flow.community_flow_id)
    )
    assert isinstance(exact, SignatureEvent)
    assert correlate_eve_event(exact, [flow]) == flow

    fallback = parse_eve_line(
        _alert(
            timestamp=flow.timestamp_start.isoformat(),
            flow_id="different",
            src_ip=str(flow.src_ip),
            src_port=flow.src_port,
            dest_ip=str(flow.dst_ip),
            dest_port=flow.dst_port,
            proto=flow.protocol,
        )
    )
    assert isinstance(fallback, SignatureEvent)
    assert correlate_eve_event(fallback, [flow]) == flow


def test_suricata_toserver_metadata_corrects_reversed_sensor_direction() -> None:
    original = next(iter(DemoAdapter().flows()))
    reversed_flow = original.model_copy(
        update={
            "src_ip": original.dst_ip,
            "src_port": original.dst_port,
            "dst_ip": original.src_ip,
            "dst_port": original.src_port,
            "packets_forward": original.packets_reverse,
            "packets_reverse": original.packets_forward,
            "bytes_forward": original.bytes_reverse,
            "bytes_reverse": original.bytes_forward,
            "first_packet_directions": [
                -direction for direction in original.first_packet_directions
            ],
        }
    )
    event = parse_eve_line(
        json.dumps(
            {
                "timestamp": original.timestamp_end.isoformat(),
                "event_type": "flow",
                "community_id": original.community_flow_id,
                "src_ip": str(original.src_ip),
                "src_port": original.src_port,
                "dest_ip": str(original.dst_ip),
                "dest_port": original.dst_port,
                "proto": original.protocol,
                "flow": {
                    "state": "closed",
                    "pkts_toserver": original.packets_forward,
                    "pkts_toclient": original.packets_reverse,
                    "bytes_toserver": original.bytes_forward,
                    "bytes_toclient": original.bytes_reverse,
                },
            }
        )
    )
    assert isinstance(event, EveMetadataEvent)

    corrected = orient_flow_with_suricata(reversed_flow, event)

    assert corrected.src_ip == original.src_ip
    assert corrected.src_port == original.src_port
    assert corrected.dst_ip == original.dst_ip
    assert corrected.dst_port == original.dst_port
    assert corrected.packets_forward == original.packets_forward
    assert corrected.bytes_reverse == original.bytes_reverse
    assert corrected.first_packet_directions == original.first_packet_directions
    assert corrected.protocol_metadata["direction_basis"] == "suricata_toserver_toclient"


def test_unknown_eve_event_is_ignored() -> None:
    assert parse_eve_line('{"event_type":"stats"}') is None
