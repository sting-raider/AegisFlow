from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from typing import Literal

import numpy as np

from packages.contracts import FlowEvent


@dataclass(frozen=True)
class FeatureSpec:
    name: str
    dtype: Literal["float"]
    source: str
    missing_policy: Literal["reject"]
    minimum: float
    maximum: float
    transformation: Literal["standard_scale"]
    training_available: bool
    inference_available: bool
    introduced: str
    privacy: Literal["non_identifying", "behavioural"]


def _spec(
    name: str,
    source: str,
    maximum: float,
    privacy: Literal["non_identifying", "behavioural"] = "behavioural",
) -> FeatureSpec:
    return FeatureSpec(
        name,
        "float",
        source,
        "reject",
        0.0,
        maximum,
        "standard_scale",
        True,
        True,
        "1.0.0",
        privacy,
    )


FEATURE_REGISTRY: tuple[FeatureSpec, ...] = (
    _spec("duration_ms", "flow.duration_ms", 86_400_000),
    _spec("packets_forward", "flow.packets_forward", 1e9),
    _spec("packets_reverse", "flow.packets_reverse", 1e9),
    _spec("bytes_forward", "flow.bytes_forward", 1e15),
    _spec("bytes_reverse", "flow.bytes_reverse", 1e15),
    _spec("packet_rate", "flow.packet_rate", 1e9),
    _spec("byte_rate", "flow.byte_rate", 1e15),
    _spec("packet_length_mean", "flow.packet_length_mean", 65_535),
    _spec("packet_length_std", "flow.packet_length_std", 65_535),
    _spec("iat_mean", "flow.iat_mean", 86_400_000),
    _spec("iat_std", "flow.iat_std", 86_400_000),
    _spec("tcp_syn_count", "flow.tcp_syn_count", 1e9),
    _spec("tcp_rst_count", "flow.tcp_rst_count", 1e9),
    _spec("destination_port", "flow.dst_port", 65_535, "non_identifying"),
    _spec("forward_reverse_byte_ratio", "derived", 1e12),
    _spec("syn_ack_ratio", "derived", 1e9),
    _spec("packets_total", "derived", 2e9),
    _spec("bytes_total", "derived", 2e15),
)
FEATURE_NAMES = tuple(spec.name for spec in FEATURE_REGISTRY)


def feature_schema() -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "feature_order": list(FEATURE_NAMES),
        "features": [asdict(spec) for spec in FEATURE_REGISTRY],
    }


def flow_to_mapping(flow: FlowEvent) -> dict[str, float]:
    values = {
        "duration_ms": float(flow.duration_ms),
        "packets_forward": float(flow.packets_forward),
        "packets_reverse": float(flow.packets_reverse),
        "bytes_forward": float(flow.bytes_forward),
        "bytes_reverse": float(flow.bytes_reverse),
        "packet_rate": float(flow.packet_rate),
        "byte_rate": float(flow.byte_rate),
        "packet_length_mean": float(flow.packet_length_mean),
        "packet_length_std": float(flow.packet_length_std),
        "iat_mean": float(flow.iat_mean),
        "iat_std": float(flow.iat_std),
        "tcp_syn_count": float(flow.tcp_syn_count),
        "tcp_rst_count": float(flow.tcp_rst_count),
        "destination_port": float(flow.dst_port),
        "forward_reverse_byte_ratio": float(flow.bytes_forward / max(flow.bytes_reverse, 1)),
        "syn_ack_ratio": float(flow.tcp_syn_count / max(flow.tcp_ack_count, 1)),
        "packets_total": float(flow.packets_forward + flow.packets_reverse),
        "bytes_total": float(flow.bytes_forward + flow.bytes_reverse),
    }
    for spec in FEATURE_REGISTRY:
        value = values[spec.name]
        if not math.isfinite(value):
            raise ValueError(f"non-finite feature: {spec.name}")
        if value < spec.minimum or value > spec.maximum:
            raise ValueError(f"feature out of range: {spec.name}")
    return values


def flow_to_vector(flow: FlowEvent) -> np.ndarray:
    mapping = flow_to_mapping(flow)
    return np.asarray([[mapping[name] for name in FEATURE_NAMES]], dtype=np.float64)
