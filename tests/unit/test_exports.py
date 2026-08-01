from __future__ import annotations

from packages.common import FLOW_EXPORT_FIELDS, anonymize_ip, sanitize_flow_export


def test_flow_export_is_allowlisted_and_anonymized_per_export() -> None:
    payload = {
        "event_id": "event-1",
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.20",
        "protocol": "TCP",
        "packets_forward": 4,
        "protocol_metadata": {"payload": "must-not-leak"},
        "raw_payload": "must-not-leak",
    }
    first = sanitize_flow_export(payload, anonymize_ips=True, salt=b"first")
    repeated = sanitize_flow_export(payload, anonymize_ips=True, salt=b"first")
    second_export = sanitize_flow_export(payload, anonymize_ips=True, salt=b"second")

    assert set(first) <= set(FLOW_EXPORT_FIELDS)
    assert first == repeated
    assert first["src_ip"] == anonymize_ip("192.0.2.10", b"first")
    assert first["src_ip"] != second_export["src_ip"]
    assert "192.0.2.10" not in str(first)
    assert "payload" not in str(first)


def test_flow_export_can_preserve_addresses_only_when_explicitly_requested() -> None:
    exported = sanitize_flow_export(
        {"src_ip": "192.0.2.10", "dst_ip": "198.51.100.20"},
        anonymize_ips=False,
        salt=b"unused",
    )

    assert exported["src_ip"] == "192.0.2.10"
    assert exported["dst_ip"] == "198.51.100.20"
