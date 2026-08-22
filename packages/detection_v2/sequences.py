"""Detector-v2 packet-sequence and connection-state representation.

Shared by training replay and runtime inference: both paths call these exact functions,
so parity holds by construction. Only privacy-preserving metadata is used (sizes,
directions, timings, flag counts); payload contents never enter this module.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np

from packages.contracts import FlowEvent

SEQUENCE_SCHEMA_VERSION = "3.0.0-research-seq"
SEQUENCE_MAX_LENGTH = 20
SEQUENCE_FEATURES_PER_PACKET = 4

SEQUENCE_FEATURE_NAMES = (
    "signed_log1p_size",
    "log1p_iat_ms",
    "direction_responder",
    "relative_position",
)

CONNECTION_STATE_FEATURE_NAMES = (
    "state_syn_observed",
    "state_handshake_evidence",
    "state_reset_terminated",
    "state_fin_terminated",
    "state_half_open_suspected",
    "state_short_failed",
    "state_midstream_capture",
    "state_data_exchange",
)

OBSERVABILITY_TIERS = ("LOW", "MEDIUM", "HIGH")


@dataclass(frozen=True)
class SequenceRepresentation:
    tensor: np.ndarray
    mask: np.ndarray
    connection_state: np.ndarray
    observability: str


def _sanitize_sizes(values: list[int] | list[float]) -> list[float]:
    return [
        float(value)
        for value in values
        if math.isfinite(float(value)) and float(value) >= 0
    ]


def _sanitize_iats(values: list[int] | list[float]) -> list[float]:
    return [
        float(value)
        for value in values
        if math.isfinite(float(value)) and float(value) >= 0
    ]


def sequence_arrays(
    sizes: list[float],
    directions: list[int],
    interarrival_ms: list[float],
    *,
    max_length: int = SEQUENCE_MAX_LENGTH,
) -> tuple[np.ndarray, np.ndarray]:
    """Encode the first-N packet observation into (tensor, mask).

    Padding is explicit: every unobserved slot is zero AND masked, so a missing packet
    can never masquerade as a zero-sized packet. Lengths are truncated to their common
    prefix because a packet without complete evidence is not observable.
    """

    if max_length < 1:
        raise ValueError("sequence length must be positive")
    clean_sizes = _sanitize_sizes(list(sizes))
    clean_directions = [int(value) for value in directions if int(value) in (-1, 1)]
    clean_iats = _sanitize_iats(list(interarrival_ms))
    observed = min(len(clean_sizes), len(clean_directions), len(clean_iats), max_length)
    tensor = np.zeros((max_length, SEQUENCE_FEATURES_PER_PACKET), dtype=np.float32)
    mask = np.zeros(max_length, dtype=np.float32)
    for index in range(observed):
        sign = -1.0 if clean_directions[index] == -1 else 1.0
        iat_delta = clean_iats[index] if index else 0.0
        tensor[index] = (
            sign * math.log1p(min(clean_sizes[index], 1e9)),
            math.log1p(max(iat_delta, 0.0)) if index else 0.0,
            1.0 if clean_directions[index] == -1 else 0.0,
            # Position is normalized against the contract maximum so that any
            # evaluated tensor length shares an identical per-packet encoding.
            index / max(SEQUENCE_MAX_LENGTH - 1, 1),
        )
        mask[index] = 1.0
    return tensor, mask


def connection_state_vector(
    *,
    protocol: str,
    total_packets: int,
    syn_count: int,
    ack_count: int,
    fin_count: int,
    rst_count: int,
    psh_count: int,
    bytes_forward: int,
    bytes_reverse: int,
) -> np.ndarray:
    """Compact TCP connection-state semantics with explicit capture uncertainty."""

    is_tcp = protocol.strip().lower() == "tcp"
    syn, ack = int(syn_count) > 0, int(ack_count) > 0
    fin, rst = int(fin_count) > 0, int(rst_count) > 0
    data_exchange = int(psh_count) > 0 or (bytes_forward > 0 and bytes_reverse > 0)
    values = {
        "state_syn_observed": syn,
        "state_handshake_evidence": syn and ack,
        "state_reset_terminated": rst,
        "state_fin_terminated": fin and not rst,
        "state_half_open_suspected": syn and not ack and not rst,
        "state_short_failed": is_tcp and total_packets <= 3 and rst,
        "state_midstream_capture": is_tcp and not syn,
        "state_data_exchange": data_exchange,
    }
    if set(values) != set(CONNECTION_STATE_FEATURE_NAMES):
        raise RuntimeError("connection-state implementation does not match its registry")
    vector = np.asarray([float(bool(values[name])) for name in CONNECTION_STATE_FEATURE_NAMES])
    if not is_tcp:
        vector[:] = 0.0
        vector[list(CONNECTION_STATE_FEATURE_NAMES).index("state_data_exchange")] = (
            1.0 if data_exchange else 0.0
        )
    return vector


def observability_tier(
    *,
    protocol: str,
    total_packets: int,
    sequence_length: int,
    duration_ms: float,
    has_state_evidence: bool,
) -> str:
    """How much information this flow exposes; absence of evidence is not benignness."""

    if total_packets < 1 or sequence_length < 1:
        return "LOW"
    is_tcp_or_udp = protocol.strip().upper() in {"TCP", "UDP"}
    if total_packets >= 4 and sequence_length >= 4 and is_tcp_or_udp:
        return "HIGH" if duration_ms >= 10.0 or has_state_evidence else "MEDIUM"
    if total_packets >= 2:
        return "MEDIUM"
    return "LOW"


def sequence_representation(
    *,
    protocol: str,
    total_packets: int,
    duration_ms: float,
    sizes: list[float],
    directions: list[int],
    interarrival_ms: list[float],
    syn_count: int = 0,
    ack_count: int = 0,
    fin_count: int = 0,
    rst_count: int = 0,
    psh_count: int = 0,
    bytes_forward: int = 0,
    bytes_reverse: int = 0,
    max_length: int = SEQUENCE_MAX_LENGTH,
) -> SequenceRepresentation:
    tensor, mask = sequence_arrays(sizes, directions, interarrival_ms, max_length=max_length)
    state = connection_state_vector(
        protocol=protocol,
        total_packets=total_packets,
        syn_count=syn_count,
        ack_count=ack_count,
        fin_count=fin_count,
        rst_count=rst_count,
        psh_count=psh_count,
        bytes_forward=bytes_forward,
        bytes_reverse=bytes_reverse,
    )
    observed = int(mask.sum())
    tier = observability_tier(
        protocol=protocol,
        total_packets=total_packets,
        sequence_length=observed,
        duration_ms=duration_ms,
        has_state_evidence=bool(syn_count or fin_count or rst_count),
    )
    return SequenceRepresentation(
        tensor=tensor, mask=mask, connection_state=state, observability=tier
    )


def sequence_representation_from_flow_event(
    flow: FlowEvent, *, max_length: int = SEQUENCE_MAX_LENGTH
) -> SequenceRepresentation:
    return sequence_representation(
        protocol=flow.protocol,
        total_packets=flow.packets_forward + flow.packets_reverse,
        duration_ms=float(flow.duration_ms),
        sizes=list(flow.first_packet_sizes),
        directions=list(flow.first_packet_directions),
        interarrival_ms=list(flow.first_packet_interarrival_times),
        syn_count=flow.tcp_syn_count,
        ack_count=flow.tcp_ack_count,
        fin_count=flow.tcp_fin_count,
        rst_count=flow.tcp_rst_count,
        psh_count=flow.tcp_psh_count,
        bytes_forward=flow.bytes_forward,
        bytes_reverse=flow.bytes_reverse,
        max_length=max_length,
    )
