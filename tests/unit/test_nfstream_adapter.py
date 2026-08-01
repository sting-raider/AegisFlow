from __future__ import annotations

from types import SimpleNamespace

from packages.contracts import CaptureMode
from services.sensor.adapters import _convert_nfstream_flow


def test_nfstream_flow_is_canonical_and_payload_free() -> None:
    flow = SimpleNamespace(
        src_ip="10.0.0.2",
        src_port=50_000,
        dst_ip="10.0.0.1",
        dst_port=443,
        protocol=6,
        ip_version=4,
        expiration_id=0,
        bidirectional_first_seen_ms=1_700_000_000_000,
        bidirectional_last_seen_ms=1_700_000_000_025,
        bidirectional_duration_ms=25,
        bidirectional_packets=3,
        bidirectional_bytes=250,
        src2dst_packets=2,
        src2dst_bytes=180,
        dst2src_packets=1,
        dst2src_bytes=70,
        bidirectional_min_ps=60,
        bidirectional_max_ps=100,
        bidirectional_mean_ps=83.3,
        bidirectional_stddev_ps=16.5,
        bidirectional_min_piat_ms=5,
        bidirectional_max_piat_ms=20,
        bidirectional_mean_piat_ms=12.5,
        bidirectional_stddev_piat_ms=7.5,
        bidirectional_syn_packets=1,
        bidirectional_ack_packets=2,
        bidirectional_fin_packets=0,
        bidirectional_rst_packets=0,
        bidirectional_psh_packets=1,
        splt_ps=[60, 90, 100],
        splt_direction=[0, 1, 0],
        splt_piat_ms=[0, 5, 20],
        application_name="TLS",
        application_category_name="Web",
        application_is_guessed=False,
        application_confidence=6,
        requested_server_name="must-not-be-persisted.invalid",
    )
    event = _convert_nfstream_flow(flow, CaptureMode.PCAP, "test-sensor")
    assert str(event.src_ip) == "10.0.0.1"
    assert event.src_port == 443
    assert event.packets_forward == 1
    assert event.packets_reverse == 2
    assert event.first_packet_directions == [-1, 1, -1]
    assert event.source_adapter == "nfstream-6.6.0"
    assert "requested_server_name" not in event.protocol_metadata
