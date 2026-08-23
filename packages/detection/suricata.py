from __future__ import annotations

import hashlib
import json
from collections import OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, cast
from uuid import NAMESPACE_URL, UUID, uuid5

from packages.common import community_id_v1, is_community_id_v1
from packages.contracts import FlowEvent, Severity, SignatureEvent

MAX_EVE_LINE_BYTES = 1024 * 1024
SUPPORTED_EVE_TYPES = {"alert", "anomaly", "flow", "dns", "tls", "http"}
EveEventType = Literal["anomaly", "flow", "dns", "tls", "http"]


class EveParseError(ValueError):
    pass


@dataclass(frozen=True)
class EveMetadataEvent:
    event_id: UUID
    timestamp: datetime
    event_type: EveEventType
    community_flow_id: str
    raw_event_hash: str
    src_ip: str | None
    src_port: int | None
    dst_ip: str | None
    dst_port: int | None
    protocol: str | None
    metadata: dict[str, str | int | float | bool]


@dataclass(frozen=True)
class EveProcessingError:
    error: str


@dataclass(frozen=True)
class EveReadBatch:
    events: tuple[SignatureEvent | EveMetadataEvent, ...]
    errors: tuple[EveProcessingError, ...]
    duplicates: int = 0


@dataclass(frozen=True)
class EveReaderHealth:
    parsed_events: int
    malformed_events: int
    duplicate_events: int


def _timestamp(value: Any) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(UTC)


def _primitive(value: Any, *, max_length: int = 256) -> str | int | float | bool | None:
    if isinstance(value, str):
        return value[:max_length]
    if isinstance(value, bool | int | float):
        return value
    return None


def _hashed_text(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _common_metadata(event: dict[str, Any]) -> dict[str, str | int | float | bool]:
    result: dict[str, str | int | float | bool] = {}
    for output, source in (
        ("src_ip", "src_ip"),
        ("src_port", "src_port"),
        ("dst_ip", "dest_ip"),
        ("dst_port", "dest_port"),
        ("proto", "proto"),
        ("app_proto", "app_proto"),
    ):
        value = _primitive(event.get(source), max_length=128)
        if value is not None:
            result[output] = value
    return result


def _flow_identifier(event: dict[str, Any]) -> str:
    explicit = event.get("community_id")
    if explicit is not None:
        if not is_community_id_v1(explicit):
            raise ValueError("event has an invalid Community ID v1 value")
        return str(explicit)
    src_ip = event.get("src_ip")
    src_port = event.get("src_port")
    dst_ip = event.get("dest_ip")
    dst_port = event.get("dest_port")
    protocol = event.get("proto")
    if all(value is not None for value in (src_ip, src_port, dst_ip, dst_port, protocol)):
        return community_id_v1(
            str(src_ip),
            int(cast(Any, src_port)),
            str(dst_ip),
            int(cast(Any, dst_port)),
            str(protocol),
        )
    native = event.get("flow_id")
    if native is None or not str(native):
        raise ValueError("event has no Community ID, native flow ID, or complete endpoint tuple")
    native_hash = hashlib.sha256(str(native).encode()).hexdigest()[:32]
    return f"suricata-flow:{native_hash}"


def _event_metadata(event_type: str, event: dict[str, Any]) -> dict[str, str | int | float | bool]:
    metadata = _common_metadata(event)
    section = event.get(event_type)
    if not isinstance(section, dict):
        raise ValueError(f"{event_type} event is missing structured metadata")
    nested: dict[str, Any] = {}
    if event_type == "dns":
        queries = section.get("queries")
        if isinstance(queries, list) and queries and isinstance(queries[0], dict):
            nested = queries[0]
    keys: dict[str, tuple[str, ...]] = {
        "anomaly": ("type", "event", "layer"),
        "flow": (
            "state",
            "reason",
            "age",
            "pkts_toserver",
            "pkts_toclient",
            "bytes_toserver",
            "bytes_toclient",
        ),
        "dns": ("type", "rrtype", "rcode", "tx_id"),
        "tls": ("version", "notbefore", "notafter", "ja3", "ja3s"),
        "http": ("http_method", "protocol", "status", "length"),
    }
    for key in keys[event_type]:
        value = _primitive(section.get(key, nested.get(key)))
        if value is not None:
            metadata[f"{event_type}_{key}"] = value
    private_names = {
        "dns": ("rrname",),
        "tls": ("sni", "subject", "issuerdn"),
        "http": ("hostname",),
    }
    for key in private_names.get(event_type, ()):
        digest = _hashed_text(section.get(key, nested.get(key)))
        if digest:
            metadata[f"{event_type}_{key}_sha256"] = digest
    return metadata


def parse_eve_line(line: bytes | str) -> SignatureEvent | EveMetadataEvent | None:
    raw = line.encode() if isinstance(line, str) else line
    if len(raw) > MAX_EVE_LINE_BYTES:
        raise EveParseError("EVE line exceeds 1 MiB")
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise EveParseError("malformed or partially written EVE JSON") from exc
    if not isinstance(decoded, dict):
        raise EveParseError("EVE event must be a JSON object")
    event: dict[str, Any] = decoded
    event_type = event.get("event_type")
    if event_type not in SUPPORTED_EVE_TYPES:
        return None
    raw_hash = hashlib.sha256(raw).hexdigest()
    try:
        timestamp = _timestamp(event["timestamp"])
        flow_identifier = _flow_identifier(event)
        if event_type == "alert":
            alert = event.get("alert")
            if not isinstance(alert, dict):
                raise ValueError("alert event is missing structured alert metadata")
            severity_number = int(alert.get("severity", 3))
            severity = {
                1: Severity.CRITICAL,
                2: Severity.HIGH,
                3: Severity.MEDIUM,
            }.get(severity_number, Severity.LOW)
            return SignatureEvent(
                event_id=uuid5(NAMESPACE_URL, f"aegisflow-suricata:{raw_hash}"),
                timestamp=timestamp,
                community_flow_id=flow_identifier,
                signature_id=str(alert["signature_id"]),
                signature_name=str(alert["signature"])[:512],
                category=str(alert.get("category", "unknown"))[:256],
                severity=severity,
                source="suricata",
                raw_event_hash=raw_hash,
                metadata=_common_metadata(event),
            )
        metadata_type = cast(EveEventType, event_type)
        metadata = _event_metadata(metadata_type, event)
        return EveMetadataEvent(
            event_id=uuid5(NAMESPACE_URL, f"aegisflow-suricata:{raw_hash}"),
            timestamp=timestamp,
            event_type=metadata_type,
            community_flow_id=flow_identifier,
            raw_event_hash=raw_hash,
            src_ip=str(event["src_ip"]) if event.get("src_ip") is not None else None,
            src_port=int(event["src_port"]) if event.get("src_port") is not None else None,
            dst_ip=str(event["dest_ip"]) if event.get("dest_ip") is not None else None,
            dst_port=int(event["dest_port"]) if event.get("dest_port") is not None else None,
            protocol=str(event["proto"]) if event.get("proto") is not None else None,
            metadata=metadata,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise EveParseError(f"incomplete EVE {event_type} event") from exc


def _event_endpoints(
    event: SignatureEvent | EveMetadataEvent,
) -> tuple[tuple[str, int], tuple[str, int], str] | None:
    if isinstance(event, EveMetadataEvent):
        src_ip: object = event.src_ip
        src_port: object = event.src_port
        dst_ip: object = event.dst_ip
        dst_port: object = event.dst_port
        protocol: object = event.protocol
    else:
        src_ip = event.metadata.get("src_ip")
        src_port = event.metadata.get("src_port")
        dst_ip = event.metadata.get("dst_ip")
        dst_port = event.metadata.get("dst_port")
        protocol = event.metadata.get("proto")
    if not isinstance(src_ip, str) or not isinstance(dst_ip, str):
        return None
    if not isinstance(src_port, int) or not isinstance(dst_port, int):
        return None
    if not isinstance(protocol, str):
        return None
    first, second = sorted(((src_ip, src_port), (dst_ip, dst_port)))
    return first, second, protocol.upper()


def correlate_eve_event(
    event: SignatureEvent | EveMetadataEvent,
    flows: Iterable[FlowEvent],
    *,
    tolerance: timedelta = timedelta(seconds=3),
) -> FlowEvent | None:
    candidates = list(flows)
    for flow in candidates:
        if event.community_flow_id == flow.community_flow_id:
            return flow
    endpoints = _event_endpoints(event)
    if endpoints is None:
        return None
    matched: list[tuple[float, FlowEvent]] = []
    for flow in candidates:
        flow_endpoints = tuple(
            sorted(
                (
                    (str(flow.src_ip), flow.src_port),
                    (str(flow.dst_ip), flow.dst_port),
                )
            )
        )
        if (*flow_endpoints, flow.protocol.upper()) != endpoints:
            continue
        if flow.timestamp_start - tolerance <= event.timestamp <= flow.timestamp_end + tolerance:
            distance = abs((event.timestamp - flow.timestamp_start).total_seconds())
            matched.append((distance, flow))
    return min(matched, key=lambda item: item[0])[1] if matched else None


def orient_flow_with_suricata(flow: FlowEvent, event: EveMetadataEvent) -> FlowEvent:
    """Apply authoritative Suricata toserver/toclient direction to a correlated flow.

    Community ID remains direction-independent. The semantic endpoints and directional
    feature fields are changed only when a complete EVE flow record proves orientation.
    """

    if event.event_type != "flow":
        return flow
    counters = {
        key: event.metadata.get(f"flow_{key}")
        for key in (
            "pkts_toserver",
            "pkts_toclient",
            "bytes_toserver",
            "bytes_toclient",
        )
    }
    if not all(
        isinstance(value, int) and not isinstance(value, bool) for value in counters.values()
    ):
        return flow
    if None in (event.src_ip, event.src_port, event.dst_ip, event.dst_port):
        return flow
    event_source = (str(event.src_ip), int(cast(int, event.src_port)))
    event_destination = (str(event.dst_ip), int(cast(int, event.dst_port)))
    flow_source = (str(flow.src_ip), flow.src_port)
    flow_destination = (str(flow.dst_ip), flow.dst_port)
    if {event_source, event_destination} != {flow_source, flow_destination}:
        raise ValueError("correlated Suricata flow endpoints do not match the sensor flow")

    metadata = {
        **flow.protocol_metadata,
        "direction_basis": "suricata_toserver_toclient",
        "suricata_pkts_toserver": cast(int, counters["pkts_toserver"]),
        "suricata_pkts_toclient": cast(int, counters["pkts_toclient"]),
        "suricata_bytes_toserver": cast(int, counters["bytes_toserver"]),
        "suricata_bytes_toclient": cast(int, counters["bytes_toclient"]),
    }
    if event_source == flow_source:
        return flow.model_copy(update={"protocol_metadata": metadata})
    return flow.model_copy(
        update={
            "src_ip": flow.dst_ip,
            "src_port": flow.dst_port,
            "dst_ip": flow.src_ip,
            "dst_port": flow.src_port,
            "packets_forward": flow.packets_reverse,
            "packets_reverse": flow.packets_forward,
            "bytes_forward": flow.bytes_reverse,
            "bytes_reverse": flow.bytes_forward,
            "first_packet_directions": [-direction for direction in flow.first_packet_directions],
            "protocol_metadata": metadata,
        }
    )


class EveDeduplicator:
    def __init__(self, max_entries: int = 50_000) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be positive")
        self.max_entries = max_entries
        self._keys: OrderedDict[tuple[object, ...], None] = OrderedDict()

    def is_duplicate(self, event: SignatureEvent | EveMetadataEvent) -> bool:
        timestamp_bucket = int(event.timestamp.timestamp())
        if isinstance(event, SignatureEvent):
            key: tuple[object, ...] = (
                "alert",
                event.signature_id,
                event.community_flow_id,
                timestamp_bucket,
                event.raw_event_hash,
            )
        else:
            key = (
                event.event_type,
                event.community_flow_id,
                timestamp_bucket,
                event.raw_event_hash,
            )
        if key in self._keys:
            self._keys.move_to_end(key)
            return True
        self._keys[key] = None
        if len(self._keys) > self.max_entries:
            self._keys.popitem(last=False)
        return False


class EveJsonReader:
    """Incremental bounded EVE reader that retains partial lines and surfaces errors."""

    def __init__(self, deduplicator: EveDeduplicator | None = None) -> None:
        self._buffer = b""
        self._deduplicator = deduplicator or EveDeduplicator()
        self._parsed_events = 0
        self._malformed_events = 0
        self._duplicate_events = 0

    def feed(self, chunk: bytes, *, final: bool = False) -> EveReadBatch:
        self._buffer += chunk
        if len(self._buffer) > MAX_EVE_LINE_BYTES and b"\n" not in self._buffer:
            self._buffer = b""
            self._malformed_events += 1
            return EveReadBatch((), (EveProcessingError("EVE line exceeds 1 MiB"),))
        lines = self._buffer.split(b"\n")
        self._buffer = b"" if final else lines.pop()
        events: list[SignatureEvent | EveMetadataEvent] = []
        errors: list[EveProcessingError] = []
        duplicates = 0
        for raw in lines:
            if not raw.strip():
                continue
            try:
                event = parse_eve_line(raw)
            except EveParseError as exc:
                errors.append(EveProcessingError(str(exc)))
                self._malformed_events += 1
                continue
            if event is None:
                continue
            if self._deduplicator.is_duplicate(event):
                duplicates += 1
                self._duplicate_events += 1
                continue
            events.append(event)
            self._parsed_events += 1
        return EveReadBatch(tuple(events), tuple(errors), duplicates)

    @property
    def health(self) -> EveReaderHealth:
        return EveReaderHealth(
            parsed_events=self._parsed_events,
            malformed_events=self._malformed_events,
            duplicate_events=self._duplicate_events,
        )
