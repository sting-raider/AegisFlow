from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from packages.common import community_id_v1
from packages.contracts import CaptureMode
from packages.features import flow_to_mapping
from services.sensor import adapters
from services.sensor.adapters import _convert_nfstream_flow


def test_windows_npcap_bootstrap_is_inherited_by_nfstream_workers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handle = object()
    added: list[str] = []
    monkeypatch.setattr(adapters, "_NPCAP_DLL_HANDLE", None)
    monkeypatch.setattr(adapters.platform, "system", lambda: "Windows")
    monkeypatch.setattr(adapters.os.path, "isdir", lambda _path: True)
    monkeypatch.setattr(
        adapters.os,
        "add_dll_directory",
        lambda path: added.append(path) or handle,
        raising=False,
    )
    monkeypatch.setenv("PYTHONPATH", r"C:\Tools")

    adapters._prepare_nfstream_runtime()
    adapters._prepare_nfstream_runtime()

    assert os.environ["PYTHONPATH"].split(os.pathsep)[0] == str(
        adapters._NFSTREAM_WINDOWS_BOOTSTRAP
    )
    assert added == [r"C:\Windows\System32\Npcap"]
    assert adapters._NPCAP_DLL_HANDLE is handle


def test_windows_live_friendly_name_resolves_to_npcap_device(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    device = r"\Device\NPF_{4CA251FD-DA57-4E10-9F1A-43187DBD3A4C}"
    monkeypatch.setattr(adapters.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        adapters,
        "_windows_npcap_interfaces",
        lambda: {"wi-fi": device},
    )

    adapter = adapters.NfstreamAdapter("Wi-Fi", capture_mode=CaptureMode.LIVE)

    assert adapter.source == device


def test_nfstream_flow_preserves_semantic_direction_and_is_payload_free() -> None:
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
    assert str(event.src_ip) == "10.0.0.2"
    assert event.src_port == 50_000
    assert str(event.dst_ip) == "10.0.0.1"
    assert event.dst_port == 443
    assert event.packets_forward == 2
    assert event.packets_reverse == 1
    assert event.bytes_forward == 180
    assert event.bytes_reverse == 70
    assert event.first_packet_directions == [1, -1, 1]
    assert flow_to_mapping(event)["destination_port"] == 443
    assert event.community_flow_id == community_id_v1("10.0.0.2", 50_000, "10.0.0.1", 443, "TCP")
    assert event.protocol_metadata["direction_basis"] == "nfstream_first_packet_src2dst"
    assert event.protocol_metadata["capture_mode"] == "pcap"
    assert event.source_adapter == "nfstream-6.6.0"
    assert "requested_server_name" not in event.protocol_metadata

    midstream = SimpleNamespace(**vars(flow))
    midstream.src_ip, midstream.dst_ip = flow.dst_ip, flow.src_ip
    midstream.src_port, midstream.dst_port = flow.dst_port, flow.src_port
    midstream.src2dst_packets, midstream.dst2src_packets = (
        flow.dst2src_packets,
        flow.src2dst_packets,
    )
    midstream.src2dst_bytes, midstream.dst2src_bytes = (
        flow.dst2src_bytes,
        flow.src2dst_bytes,
    )
    midstream.splt_direction = [1 - value for value in flow.splt_direction]

    corrected = _convert_nfstream_flow(midstream, CaptureMode.PCAP, "test-sensor")

    assert corrected.src_ip == event.src_ip
    assert corrected.src_port == event.src_port
    assert corrected.dst_ip == event.dst_ip
    assert corrected.dst_port == event.dst_port
    assert corrected.packets_forward == event.packets_forward
    assert corrected.bytes_reverse == event.bytes_reverse
    assert corrected.first_packet_directions == event.first_packet_directions
    assert corrected.protocol_metadata["direction_basis"] == ("well_known_service_ephemeral_client")
