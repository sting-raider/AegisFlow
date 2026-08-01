from __future__ import annotations

import hashlib
import platform
from abc import ABC, abstractmethod
from collections import defaultdict
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from itertools import pairwise
from pathlib import Path
from statistics import fmean, pstdev
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from packages.contracts import CaptureMode, FlowEvent


class SensorAdapter(ABC):
    @abstractmethod
    def flows(self) -> Iterable[FlowEvent]:
        """Yield completed, validated flows."""


def _community_id(parts: tuple[object, ...]) -> str:
    return "1:" + hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:32]


def _demo_flow(
    name: str,
    offset: int,
    *,
    dst_port: int,
    packets_forward: int,
    packets_reverse: int,
    bytes_forward: int,
    bytes_reverse: int,
    syn: int = 1,
    rst: int = 0,
    duration_ms: float = 900,
    metadata: dict[str, str | int | float | bool] | None = None,
) -> FlowEvent:
    started = datetime(2026, 1, 15, 9, 0, tzinfo=UTC) + timedelta(seconds=offset)
    packets = packets_forward + packets_reverse
    total_bytes = bytes_forward + bytes_reverse
    seconds = max(duration_ms / 1000, 0.001)
    mean_size = total_bytes / max(packets, 1)
    return FlowEvent(
        event_id=uuid5(NAMESPACE_URL, f"aegisflow-demo:{name}:{offset}"),
        sensor_id="demo-sensor-01",
        capture_mode=CaptureMode.DEMO,
        timestamp_start=started,
        timestamp_end=started + timedelta(milliseconds=duration_ms),
        duration_ms=duration_ms,
        src_ip=ip_address("10.20.0.15"),
        dst_ip=ip_address(f"198.51.100.{10 + offset}"),
        src_port=50_000 + offset,
        dst_port=dst_port,
        ip_version=4,
        protocol="TCP",
        application_protocol={53: "dns", 80: "http", 443: "tls"}.get(dst_port),
        direction="outbound",
        packets_forward=packets_forward,
        packets_reverse=packets_reverse,
        bytes_forward=bytes_forward,
        bytes_reverse=bytes_reverse,
        packet_rate=packets / seconds,
        byte_rate=total_bytes / seconds,
        packet_length_min=max(40, mean_size * 0.2),
        packet_length_max=min(65_535, mean_size * 2.2),
        packet_length_mean=mean_size,
        packet_length_std=mean_size * 0.25,
        iat_min=0.1,
        iat_max=max(duration_ms / max(packets, 1), 0.1) * 2,
        iat_mean=duration_ms / max(packets, 1),
        iat_std=duration_ms / max(packets, 1) * 0.3,
        tcp_syn_count=syn,
        tcp_ack_count=max(packets_reverse, 1),
        tcp_rst_count=rst,
        first_packet_sizes=[64, 72, min(int(mean_size), 1500)],
        first_packet_directions=[1, -1, 1],
        first_packet_interarrival_times=[0.0, 3.2, 8.7],
        community_flow_id=_community_id((name, offset, dst_port)),
        source_adapter="synthetic-v1",
        protocol_metadata={"scenario": name, **(metadata or {})},
    )


class DemoAdapter(SensorAdapter):
    def flows(self) -> Iterable[FlowEvent]:
        yield _demo_flow(
            "ordinary-web",
            0,
            dst_port=443,
            packets_forward=12,
            packets_reverse=15,
            bytes_forward=2500,
            bytes_reverse=18_000,
            duration_ms=1200,
        )
        yield _demo_flow(
            "ordinary-dns",
            1,
            dst_port=53,
            packets_forward=2,
            packets_reverse=2,
            bytes_forward=150,
            bytes_reverse=420,
            duration_ms=80,
        )
        yield _demo_flow(
            "known-signature",
            2,
            dst_port=22,
            packets_forward=130,
            packets_reverse=70,
            bytes_forward=28_000,
            bytes_reverse=32_000,
            syn=90,
            rst=35,
            duration_ms=6000,
        )
        yield _demo_flow(
            "port-fanout",
            3,
            dst_port=31_337,
            packets_forward=145,
            packets_reverse=1,
            bytes_forward=9400,
            bytes_reverse=40,
            syn=140,
            rst=18,
            duration_ms=850,
            metadata={"distinct_destination_ports": 48},
        )
        yield _demo_flow(
            "connection-burst",
            4,
            dst_port=3389,
            packets_forward=320,
            packets_reverse=110,
            bytes_forward=65_000,
            bytes_reverse=44_000,
            syn=205,
            rst=70,
            duration_ms=720,
        )
        yield _demo_flow(
            "novel-outbound-transfer",
            5,
            dst_port=8443,
            packets_forward=600_000,
            packets_reverse=18,
            bytes_forward=780_000_000,
            bytes_reverse=12_000,
            syn=2,
            duration_ms=14_000,
        )


class PcapAdapter(SensorAdapter):
    def __init__(self, path: Path, sensor_id: str = "pcap-sensor") -> None:
        self.path = path.resolve()
        self.sensor_id = sensor_id
        if not self.path.is_file():
            raise FileNotFoundError(self.path)
        if self.path.suffix.lower() not in {".pcap", ".pcapng"}:
            raise ValueError("capture must have .pcap or .pcapng extension")
        if self.path.stat().st_size > 512 * 1024 * 1024:
            raise ValueError("capture exceeds the 512 MiB offline safety limit")

    def flows(self) -> Iterable[FlowEvent]:
        from scapy.all import IP, TCP, UDP, IPv6, PcapReader

        buckets: dict[tuple[Any, ...], list[tuple[float, int, int, Any]]] = defaultdict(list)
        with PcapReader(str(self.path)) as reader:
            for index, packet in enumerate(reader):
                if index >= 2_000_000:
                    raise ValueError("capture exceeds the two-million packet safety limit")
                network = packet.getlayer(IP) or packet.getlayer(IPv6)
                transport = packet.getlayer(TCP) or packet.getlayer(UDP)
                if network is None or transport is None:
                    continue
                a = (str(network.src), int(transport.sport))
                b = (str(network.dst), int(transport.dport))
                endpoints = tuple(sorted((a, b)))
                protocol = "TCP" if packet.haslayer(TCP) else "UDP"
                key = (*endpoints[0], *endpoints[1], protocol)
                direction = 1 if a == endpoints[0] else -1
                buckets[key].append((float(packet.time), len(packet), direction, packet))
        for key, packets in buckets.items():
            yield self._convert(key, packets)

    def _convert(
        self, key: tuple[Any, ...], packets: list[tuple[float, int, int, Any]]
    ) -> FlowEvent:
        packets.sort(key=lambda item: item[0])
        src_ip, src_port, dst_ip, dst_port, protocol = key
        times = [item[0] for item in packets]
        sizes = [item[1] for item in packets]
        directions = [item[2] for item in packets]
        iats = [max((b - a) * 1000, 0.0) for a, b in pairwise(times)]
        forward = [
            size for size, direction in zip(sizes, directions, strict=True) if direction == 1
        ]
        reverse = [
            size for size, direction in zip(sizes, directions, strict=True) if direction == -1
        ]
        tcp_flags = {"S": 0, "A": 0, "F": 0, "R": 0, "P": 0}
        if protocol == "TCP":
            for _, _, _, packet in packets:
                flags = str(packet["TCP"].flags)
                for flag in tcp_flags:
                    tcp_flags[flag] += int(flag in flags)
        duration_ms = max((times[-1] - times[0]) * 1000, 0.001)
        endpoint_version = ip_address(src_ip).version
        return FlowEvent(
            sensor_id=self.sensor_id,
            capture_mode=CaptureMode.PCAP,
            timestamp_start=datetime.fromtimestamp(times[0], UTC),
            timestamp_end=datetime.fromtimestamp(times[-1], UTC),
            duration_ms=duration_ms,
            src_ip=ip_address(src_ip),
            dst_ip=ip_address(dst_ip),
            src_port=src_port,
            dst_port=dst_port,
            ip_version=endpoint_version,
            protocol=protocol,
            application_protocol=None,
            packets_forward=len(forward),
            packets_reverse=len(reverse),
            bytes_forward=sum(forward),
            bytes_reverse=sum(reverse),
            packet_rate=len(packets) / (duration_ms / 1000),
            byte_rate=sum(sizes) / (duration_ms / 1000),
            packet_length_min=min(sizes),
            packet_length_max=max(sizes),
            packet_length_mean=fmean(sizes),
            packet_length_std=pstdev(sizes),
            iat_min=min(iats, default=0),
            iat_max=max(iats, default=0),
            iat_mean=fmean(iats) if iats else 0,
            iat_std=pstdev(iats) if iats else 0,
            tcp_syn_count=tcp_flags["S"],
            tcp_ack_count=tcp_flags["A"],
            tcp_fin_count=tcp_flags["F"],
            tcp_rst_count=tcp_flags["R"],
            tcp_psh_count=tcp_flags["P"],
            first_packet_sizes=sizes[:20],
            first_packet_directions=directions[:20],
            first_packet_interarrival_times=[0.0, *iats[:19]],
            community_flow_id=_community_id(key),
            source_adapter="scapy-flow-v1",
        )


def _nf_value(flow: Any, name: str, default: Any = 0) -> Any:
    value = getattr(flow, name, default)
    return default if value is None else value


def _convert_nfstream_flow(flow: Any, capture_mode: CaptureMode, sensor_id: str) -> FlowEvent:
    original_source = (str(flow.src_ip), int(flow.src_port))
    original_destination = (str(flow.dst_ip), int(flow.dst_port))
    source, destination = sorted((original_source, original_destination))
    source_is_src2dst = source == original_source
    if source_is_src2dst:
        packets_forward = int(_nf_value(flow, "src2dst_packets"))
        packets_reverse = int(_nf_value(flow, "dst2src_packets"))
        bytes_forward = int(_nf_value(flow, "src2dst_bytes"))
        bytes_reverse = int(_nf_value(flow, "dst2src_bytes"))
    else:
        packets_forward = int(_nf_value(flow, "dst2src_packets"))
        packets_reverse = int(_nf_value(flow, "src2dst_packets"))
        bytes_forward = int(_nf_value(flow, "dst2src_bytes"))
        bytes_reverse = int(_nf_value(flow, "src2dst_bytes"))

    duration_ms = max(float(_nf_value(flow, "bidirectional_duration_ms", 0.001)), 0.001)
    packets = max(int(_nf_value(flow, "bidirectional_packets")), 1)
    total_bytes = max(int(_nf_value(flow, "bidirectional_bytes")), 0)
    first_seen_ms = int(_nf_value(flow, "bidirectional_first_seen_ms"))
    last_seen_ms = max(int(_nf_value(flow, "bidirectional_last_seen_ms")), first_seen_ms)
    protocol_number = int(_nf_value(flow, "protocol"))
    protocol = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPV6"}.get(
        protocol_number, str(protocol_number)
    )
    splt_length = min(packets, 20)
    raw_sizes = list(_nf_value(flow, "splt_ps", []))[:splt_length]
    raw_directions = list(_nf_value(flow, "splt_direction", []))[:splt_length]
    raw_iats = list(_nf_value(flow, "splt_piat_ms", []))[:splt_length]
    sizes = [max(int(value), 0) for value in raw_sizes]
    directions = [
        (1 if int(value) == 0 else -1) * (1 if source_is_src2dst else -1)
        for value in raw_directions
    ]
    iats = [max(float(value), 0.0) for value in raw_iats]
    application = str(_nf_value(flow, "application_name", "")).strip() or None
    metadata: dict[str, str | int | float | bool] = {
        "nfstream_expiration_id": int(_nf_value(flow, "expiration_id")),
        "application_is_guessed": bool(_nf_value(flow, "application_is_guessed", False)),
        "application_confidence": float(_nf_value(flow, "application_confidence", 0.0)),
    }
    category = str(_nf_value(flow, "application_category_name", "")).strip()
    if category:
        metadata["application_category"] = category[:128]
    key = (*source, *destination, protocol)
    return FlowEvent(
        event_id=uuid5(
            NAMESPACE_URL,
            f"aegisflow-nfstream:{capture_mode.value}:{sensor_id}:{first_seen_ms}:{key}",
        ),
        sensor_id=sensor_id,
        capture_mode=capture_mode,
        timestamp_start=datetime.fromtimestamp(first_seen_ms / 1000, UTC),
        timestamp_end=datetime.fromtimestamp(last_seen_ms / 1000, UTC),
        duration_ms=duration_ms,
        src_ip=ip_address(source[0]),
        dst_ip=ip_address(destination[0]),
        src_port=source[1],
        dst_port=destination[1],
        ip_version=int(_nf_value(flow, "ip_version")),
        protocol=protocol,
        application_protocol=application[:64] if application else None,
        direction="unknown",
        packets_forward=packets_forward,
        packets_reverse=packets_reverse,
        bytes_forward=bytes_forward,
        bytes_reverse=bytes_reverse,
        packet_rate=packets / (duration_ms / 1000),
        byte_rate=total_bytes / (duration_ms / 1000),
        packet_length_min=max(float(_nf_value(flow, "bidirectional_min_ps")), 0.0),
        packet_length_max=max(float(_nf_value(flow, "bidirectional_max_ps")), 0.0),
        packet_length_mean=max(float(_nf_value(flow, "bidirectional_mean_ps")), 0.0),
        packet_length_std=max(float(_nf_value(flow, "bidirectional_stddev_ps")), 0.0),
        iat_min=max(float(_nf_value(flow, "bidirectional_min_piat_ms")), 0.0),
        iat_max=max(float(_nf_value(flow, "bidirectional_max_piat_ms")), 0.0),
        iat_mean=max(float(_nf_value(flow, "bidirectional_mean_piat_ms")), 0.0),
        iat_std=max(float(_nf_value(flow, "bidirectional_stddev_piat_ms")), 0.0),
        tcp_syn_count=int(_nf_value(flow, "bidirectional_syn_packets")),
        tcp_ack_count=int(_nf_value(flow, "bidirectional_ack_packets")),
        tcp_fin_count=int(_nf_value(flow, "bidirectional_fin_packets")),
        tcp_rst_count=int(_nf_value(flow, "bidirectional_rst_packets")),
        tcp_psh_count=int(_nf_value(flow, "bidirectional_psh_packets")),
        first_packet_sizes=sizes,
        first_packet_directions=directions,
        first_packet_interarrival_times=iats,
        community_flow_id=_community_id(key),
        source_adapter="nfstream-6.6.0",
        protocol_metadata=metadata,
    )


class NfstreamAdapter(SensorAdapter):
    """NFStream completed-flow adapter for bounded PCAP or explicit Linux live capture."""

    def __init__(
        self,
        source: Path | str,
        *,
        capture_mode: CaptureMode = CaptureMode.PCAP,
        sensor_id: str = "nfstream-sensor",
        idle_timeout: int = 120,
        active_timeout: int = 1800,
        max_flows: int = 0,
    ) -> None:
        if capture_mode == CaptureMode.DEMO:
            raise ValueError("NFStream is available only for PCAP or live capture")
        if capture_mode == CaptureMode.LIVE:
            if platform.system() != "Linux":
                raise RuntimeError("live capture is supported only on Linux; use demo or PCAP mode")
            if not isinstance(source, str) or not source.strip():
                raise ValueError("live capture requires an explicit interface")
            self.source = source.strip()
        else:
            path = Path(source).resolve()
            if not path.is_file():
                raise FileNotFoundError(path)
            if path.suffix.lower() not in {".pcap", ".pcapng"}:
                raise ValueError("capture must have .pcap or .pcapng extension")
            if path.stat().st_size > 512 * 1024 * 1024:
                raise ValueError("capture exceeds the 512 MiB offline safety limit")
            self.source = str(path)
        self.capture_mode = capture_mode
        self.sensor_id = sensor_id
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self.max_flows = max_flows

    def flows(self) -> Iterable[FlowEvent]:
        try:
            from nfstream import NFStreamer
        except (ImportError, OSError) as exc:
            raise RuntimeError(
                "NFStream native capture engine is unavailable; use Scapy PCAP or the "
                "documented Suricata EVE adapter"
            ) from exc
        streamer = NFStreamer(
            source=self.source,
            promiscuous_mode=self.capture_mode != CaptureMode.LIVE,
            statistical_analysis=True,
            splt_analysis=20,
            n_dissections=20,
            idle_timeout=self.idle_timeout,
            active_timeout=self.active_timeout,
            max_nflows=self.max_flows,
            n_meters=1 if self.capture_mode == CaptureMode.LIVE else 0,
        )
        for flow in streamer:
            yield _convert_nfstream_flow(flow, self.capture_mode, self.sensor_id)


class LiveAdapter(SensorAdapter):
    def __init__(self, interface: str | None) -> None:
        if not interface:
            raise ValueError("live capture requires an explicit interface")
        if platform.system() != "Linux":
            raise RuntimeError("live capture is supported only on Linux; use demo or PCAP mode")
        self.interface = interface

    def flows(self) -> Iterable[FlowEvent]:
        return NfstreamAdapter(
            self.interface,
            capture_mode=CaptureMode.LIVE,
            sensor_id="live-nfstream-sensor",
        ).flows()
