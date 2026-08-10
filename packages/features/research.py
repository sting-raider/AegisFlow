from __future__ import annotations

import math
from collections import Counter, OrderedDict
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import datetime
from ipaddress import ip_address
from itertools import pairwise
from statistics import fmean, pstdev
from threading import RLock

import numpy as np

from packages.contracts import FlowEvent

PORTABLE_SCHEMA_VERSION = "2.0.0-research-a"
TEMPORAL_SCHEMA_VERSION = "2.0.0-research-b"

PORTABLE_FEATURE_NAMES = (
    "duration_log1p_ms",
    "packets_total_log1p",
    "packets_forward_fraction",
    "bytes_total_log1p",
    "bytes_forward_fraction",
    "packet_rate_log1p_derived",
    "byte_rate_log1p_derived",
    "packet_length_mean_log1p_derived",
    "forward_reverse_byte_log_ratio",
    "protocol_tcp",
    "protocol_udp",
    "protocol_icmp",
    "protocol_other",
    "destination_port_missing",
    "port_well_known",
    "port_registered",
    "port_dynamic",
    "service_dns",
    "service_web",
    "service_mail",
    "service_remote_access",
    "service_file_transfer",
    "service_database",
    "service_other",
)

PORTABLE_DATASET_SENSITIVE_FEATURE_NAMES = tuple(
    name
    for name in PORTABLE_FEATURE_NAMES
    if name.startswith(("protocol_", "port_", "service_"))
    or name == "destination_port_missing"
)
PORTABLE_NUMERICAL_CORE_FEATURE_NAMES = tuple(
    name
    for name in PORTABLE_FEATURE_NAMES
    if name not in PORTABLE_DATASET_SENSITIVE_FEATURE_NAMES
)

TEMPORAL_FEATURE_NAMES = (
    "source_flows_10s_log1p",
    "source_flows_60s_log1p",
    "unique_destinations_10s_log1p",
    "unique_destinations_60s_log1p",
    "unique_destination_ports_10s_log1p",
    "unique_destination_ports_60s_log1p",
    "destination_novelty_60s",
    "service_port_rarity_60s",
    "protocol_rarity_60s",
    "destination_fanout_entropy_60s",
    "connection_interval_mean_log1p_ms_60s",
    "connection_interval_std_log1p_ms_60s",
    "connection_burstiness_60s",
    "short_lived_ratio_60s",
    "temporal_cold_start",
    "temporal_late_event",
)

RUNTIME_ENRICHED_FEATURE_NAMES = PORTABLE_FEATURE_NAMES + TEMPORAL_FEATURE_NAMES

_DNS_PORTS = {53, 853}
_WEB_PORTS = {80, 443, 8000, 8080, 8443}
_MAIL_PORTS = {25, 110, 143, 465, 587, 993, 995}
_REMOTE_PORTS = {22, 23, 3389, 5900}
_FILE_PORTS = {20, 21, 69, 115, 445, 2049}
_DATABASE_PORTS = {1433, 1521, 3306, 5432, 6379, 9042, 9200, 27017}


@dataclass(frozen=True)
class ResearchFeatureSpec:
    name: str
    source: str
    transformation: str
    missing_policy: str


@dataclass(frozen=True)
class FlowObservation:
    event_id: str
    sensor_id: str
    timestamp: datetime
    source_ip: str
    destination_ip: str
    destination_port: int | None
    protocol: str | int | None
    duration_ms: float
    packets_forward: int
    packets_reverse: int
    bytes_forward: int
    bytes_reverse: int

    @classmethod
    def from_flow_event(cls, flow: FlowEvent) -> FlowObservation:
        return cls(
            event_id=str(flow.event_id),
            sensor_id=flow.sensor_id,
            timestamp=flow.timestamp_start,
            source_ip=str(flow.src_ip),
            destination_ip=str(flow.dst_ip),
            destination_port=flow.dst_port,
            protocol=flow.protocol,
            duration_ms=float(flow.duration_ms),
            packets_forward=flow.packets_forward,
            packets_reverse=flow.packets_reverse,
            bytes_forward=flow.bytes_forward,
            bytes_reverse=flow.bytes_reverse,
        )

    def validate(self) -> None:
        if not self.event_id or not self.sensor_id:
            raise ValueError("research observation requires event_id and sensor_id")
        if self.timestamp.tzinfo is None:
            raise ValueError("research observation timestamp must be timezone-aware")
        source = ip_address(self.source_ip)
        destination = ip_address(self.destination_ip)
        if source.version != destination.version:
            raise ValueError("research observation endpoints must share an IP version")
        numeric = (
            self.duration_ms,
            self.packets_forward,
            self.packets_reverse,
            self.bytes_forward,
            self.bytes_reverse,
        )
        if any(not math.isfinite(float(value)) or value < 0 for value in numeric):
            raise ValueError("research observation numeric values must be finite and non-negative")
        if self.destination_port is not None and not 0 <= self.destination_port <= 65_535:
            raise ValueError("destination port must be in [0, 65535]")


def _protocol_group(value: str | int | None) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"6", "tcp"}:
        return "tcp"
    if normalized in {"17", "udp"}:
        return "udp"
    if normalized in {"1", "58", "icmp", "icmpv6", "icmp6"}:
        return "icmp"
    return "other"


def _service_group(port: int | None) -> str:
    if port in _DNS_PORTS:
        return "dns"
    if port in _WEB_PORTS:
        return "web"
    if port in _MAIL_PORTS:
        return "mail"
    if port in _REMOTE_PORTS:
        return "remote_access"
    if port in _FILE_PORTS:
        return "file_transfer"
    if port in _DATABASE_PORTS:
        return "database"
    return "other"


def portable_feature_mapping(observation: FlowObservation) -> dict[str, float]:
    vector = portable_feature_vector(observation)
    return dict(zip(PORTABLE_FEATURE_NAMES, vector.tolist(), strict=True))


def portable_feature_vector(observation: FlowObservation) -> np.ndarray:
    observation.validate()
    vector = portable_feature_matrix(
        duration_ms=np.asarray([observation.duration_ms]),
        packets_forward=np.asarray([observation.packets_forward]),
        packets_reverse=np.asarray([observation.packets_reverse]),
        bytes_forward=np.asarray([observation.bytes_forward]),
        bytes_reverse=np.asarray([observation.bytes_reverse]),
        destination_ports=[observation.destination_port],
        protocols=[observation.protocol],
    )[0]
    return np.asarray(vector, dtype=np.float64)


def portable_feature_matrix(
    *,
    duration_ms: np.ndarray,
    packets_forward: np.ndarray,
    packets_reverse: np.ndarray,
    bytes_forward: np.ndarray,
    bytes_reverse: np.ndarray,
    destination_ports: Sequence[int | None],
    protocols: Sequence[str | int | None],
) -> np.ndarray:
    """Canonical vectorized Schema A implementation; scalar runtime delegates here."""

    numeric = [
        np.asarray(values, dtype=np.float64)
        for values in (
            duration_ms,
            packets_forward,
            packets_reverse,
            bytes_forward,
            bytes_reverse,
        )
    ]
    rows = len(numeric[0])
    if any(values.ndim != 1 or len(values) != rows for values in numeric):
        raise ValueError("portable feature inputs must be aligned one-dimensional arrays")
    if len(destination_ports) != rows or len(protocols) != rows:
        raise ValueError("portable categorical inputs must align with numeric rows")
    if any(not np.isfinite(values).all() or np.any(values < 0) for values in numeric):
        raise ValueError("portable numeric inputs must be finite and non-negative")
    duration, packets_fwd, packets_rev, bytes_fwd, bytes_rev = numeric
    packets_total = packets_fwd + packets_rev
    bytes_total = bytes_fwd + bytes_rev
    duration_seconds = np.maximum(duration / 1000.0, 1e-6)
    ports = np.asarray(
        [np.nan if value is None else float(value) for value in destination_ports]
    )
    if np.any(np.isfinite(ports) & ((ports < 0) | (ports > 65_535))):
        raise ValueError("destination ports must be missing or in [0, 65535]")
    protocol_groups = np.asarray([_protocol_group(value) for value in protocols])
    missing_port = ~np.isfinite(ports)
    service_groups = np.asarray(
        [
            _service_group(None if missing else int(port))
            for port, missing in zip(ports, missing_port, strict=True)
        ]
    )
    matrix = np.column_stack(
        (
            np.log1p(duration),
            np.log1p(packets_total),
            packets_fwd / np.maximum(packets_total, 1.0),
            np.log1p(bytes_total),
            bytes_fwd / np.maximum(bytes_total, 1.0),
            np.log1p(packets_total / duration_seconds),
            np.log1p(bytes_total / duration_seconds),
            np.log1p(bytes_total / np.maximum(packets_total, 1.0)),
            np.log1p(bytes_fwd) - np.log1p(bytes_rev),
            protocol_groups == "tcp",
            protocol_groups == "udp",
            protocol_groups == "icmp",
            protocol_groups == "other",
            missing_port,
            (~missing_port) & (ports < 1024),
            (~missing_port) & (ports >= 1024) & (ports < 49_152),
            (~missing_port) & (ports >= 49_152),
            service_groups == "dns",
            service_groups == "web",
            service_groups == "mail",
            service_groups == "remote_access",
            service_groups == "file_transfer",
            service_groups == "database",
            service_groups == "other",
        )
    ).astype(np.float64)
    if matrix.shape != (rows, len(PORTABLE_FEATURE_NAMES)) or not np.isfinite(matrix).all():
        raise ValueError("portable feature matrix violates schema A")
    return matrix


@dataclass(frozen=True)
class _TemporalRecord:
    timestamp: float
    destination_ip: str
    destination_port: int | None
    protocol: str
    short_lived: bool


class TemporalFeatureState:
    """Bounded, sensor-scoped temporal feature implementation shared by replay/runtime."""

    def __init__(
        self,
        *,
        window_seconds: float = 60.0,
        short_window_seconds: float = 10.0,
        max_clock_skew_seconds: float = 5.0,
        max_sources: int = 10_000,
        max_events_per_source: int = 2_048,
        duplicate_capacity: int = 65_536,
    ) -> None:
        if not 0 < short_window_seconds <= window_seconds:
            raise ValueError("temporal windows must be positive and ordered")
        if max_clock_skew_seconds < 0:
            raise ValueError("max_clock_skew_seconds cannot be negative")
        if min(max_sources, max_events_per_source, duplicate_capacity) < 1:
            raise ValueError("temporal capacities must be positive")
        self.window_seconds = window_seconds
        self.short_window_seconds = short_window_seconds
        self.max_clock_skew_seconds = max_clock_skew_seconds
        self.max_sources = max_sources
        self.max_events_per_source = max_events_per_source
        self.duplicate_capacity = duplicate_capacity
        self._sources: OrderedDict[tuple[str, str], list[_TemporalRecord]] = OrderedDict()
        self._watermarks: dict[tuple[str, str], float] = {}
        self._duplicates: OrderedDict[str, np.ndarray] = OrderedDict()
        self._lock = RLock()

    @property
    def source_count(self) -> int:
        return len(self._sources)

    @property
    def event_count(self) -> int:
        return sum(len(records) for records in self._sources.values())

    def clear(self) -> None:
        with self._lock:
            self._sources.clear()
            self._watermarks.clear()
            self._duplicates.clear()

    def observe_mapping(self, observation: FlowObservation) -> dict[str, float]:
        observation.validate()
        with self._lock:
            cached = self._duplicates.get(observation.event_id)
            if cached is not None:
                self._duplicates.move_to_end(observation.event_id)
                return dict(zip(TEMPORAL_FEATURE_NAMES, cached.tolist(), strict=True))

            key = (observation.sensor_id, str(ip_address(observation.source_ip)))
            timestamp = observation.timestamp.timestamp()
            watermark = max(timestamp, self._watermarks.get(key, timestamp))
            late = timestamp < watermark
            records = self._sources.pop(key, [])
            cutoff = watermark - self.window_seconds - self.max_clock_skew_seconds
            records = [record for record in records if record.timestamp >= cutoff]
            prior = [
                record
                for record in records
                if watermark - self.window_seconds <= record.timestamp <= watermark
            ]
            too_late = timestamp < watermark - self.max_clock_skew_seconds
            if not too_late:
                records.append(
                    _TemporalRecord(
                        timestamp=timestamp,
                        destination_ip=str(ip_address(observation.destination_ip)),
                        destination_port=observation.destination_port,
                        protocol=_protocol_group(observation.protocol),
                        short_lived=observation.duration_ms <= 1_000.0,
                    )
                )
                records.sort(key=lambda item: item.timestamp)
                records = records[-self.max_events_per_source :]
            self._sources[key] = records
            self._watermarks[key] = watermark
            while len(self._sources) > self.max_sources:
                evicted, _ = self._sources.popitem(last=False)
                self._watermarks.pop(evicted, None)

            active = [
                record
                for record in records
                if watermark - self.window_seconds <= record.timestamp <= watermark
            ]
            short = [
                record
                for record in active
                if record.timestamp >= watermark - self.short_window_seconds
            ]
            values = self._mapping(observation, prior, active, short, late)
            vector = np.asarray(
                [values[name] for name in TEMPORAL_FEATURE_NAMES], dtype=np.float64
            )
            self._duplicates[observation.event_id] = vector
            while len(self._duplicates) > self.duplicate_capacity:
                self._duplicates.popitem(last=False)
            return values

    def observe_vector(self, observation: FlowObservation) -> np.ndarray:
        values = self.observe_mapping(observation)
        return np.asarray([values[name] for name in TEMPORAL_FEATURE_NAMES], dtype=np.float64)

    def observe_runtime_enriched_vector(self, observation: FlowObservation) -> np.ndarray:
        return np.concatenate(
            (portable_feature_vector(observation), self.observe_vector(observation))
        )

    @staticmethod
    def _mapping(
        observation: FlowObservation,
        prior: list[_TemporalRecord],
        active: list[_TemporalRecord],
        short: list[_TemporalRecord],
        late: bool,
    ) -> dict[str, float]:
        destinations = Counter(record.destination_ip for record in active)
        timestamps = sorted(record.timestamp for record in active)
        intervals_ms = [
            (right - left) * 1000.0
            for left, right in pairwise(timestamps)
        ]
        interval_mean = fmean(intervals_ms) if intervals_ms else 0.0
        interval_std = pstdev(intervals_ms) if len(intervals_ms) > 1 else 0.0
        entropy = 0.0
        if len(active) > 1 and len(destinations) > 1:
            entropy = -sum(
                (count / len(active)) * math.log(count / len(active))
                for count in destinations.values()
            ) / math.log(len(destinations))
        prior_ports = Counter(record.destination_port for record in prior)
        prior_protocols = Counter(record.protocol for record in prior)
        protocol = _protocol_group(observation.protocol)
        cold = not prior
        values = {
            "source_flows_10s_log1p": math.log1p(len(short)),
            "source_flows_60s_log1p": math.log1p(len(active)),
            "unique_destinations_10s_log1p": math.log1p(
                len({record.destination_ip for record in short})
            ),
            "unique_destinations_60s_log1p": math.log1p(len(destinations)),
            "unique_destination_ports_10s_log1p": math.log1p(
                len({record.destination_port for record in short})
            ),
            "unique_destination_ports_60s_log1p": math.log1p(
                len({record.destination_port for record in active})
            ),
            "destination_novelty_60s": float(
                not cold
                and str(ip_address(observation.destination_ip))
                not in {record.destination_ip for record in prior}
            ),
            "service_port_rarity_60s": (
                1.0 - prior_ports[observation.destination_port] / len(prior) if prior else 0.0
            ),
            "protocol_rarity_60s": (
                1.0 - prior_protocols[protocol] / len(prior) if prior else 0.0
            ),
            "destination_fanout_entropy_60s": entropy,
            "connection_interval_mean_log1p_ms_60s": math.log1p(interval_mean),
            "connection_interval_std_log1p_ms_60s": math.log1p(interval_std),
            "connection_burstiness_60s": interval_std / max(interval_mean + interval_std, 1e-9),
            "short_lived_ratio_60s": (
                sum(record.short_lived for record in active) / len(active) if active else 0.0
            ),
            "temporal_cold_start": float(cold),
            "temporal_late_event": float(late),
        }
        if set(values) != set(TEMPORAL_FEATURE_NAMES):
            raise RuntimeError("temporal feature implementation does not match its registry")
        if not all(math.isfinite(value) for value in values.values()):
            raise ValueError("temporal features must be finite")
        return values


def research_feature_schema() -> dict[str, object]:
    portable = [
        ResearchFeatureSpec(
            name=name,
            source="current_flow",
            transformation=(
                "one_hot"
                if name.startswith(("protocol_", "port_", "service_"))
                else "bounded_or_log1p"
            ),
            missing_policy=(
                "explicit_indicator" if name == "destination_port_missing" else "not_applicable"
            ),
        )
        for name in PORTABLE_FEATURE_NAMES
    ]
    temporal = [
        ResearchFeatureSpec(
            name=name,
            source="aegisflow_bounded_source_window",
            transformation="bounded_or_log1p",
            missing_policy="cold_start_indicator",
        )
        for name in TEMPORAL_FEATURE_NAMES
    ]
    return {
        "schema_a": {
            "version": PORTABLE_SCHEMA_VERSION,
            "feature_order": list(PORTABLE_FEATURE_NAMES),
            "features": [asdict(spec) for spec in portable],
        },
        "schema_b": {
            "version": TEMPORAL_SCHEMA_VERSION,
            "feature_order": list(RUNTIME_ENRICHED_FEATURE_NAMES),
            "features": [asdict(spec) for spec in portable + temporal],
            "state": {
                "key": ["sensor_id", "source_ip"],
                "windows_seconds": [10, 60],
                "duplicate_policy": "return_cached_without_state_mutation",
                "late_event_policy": "flag_and_ignore_for_state_when_beyond_clock_skew",
                "expiry": "bounded_window_plus_clock_skew",
            },
        },
    }
