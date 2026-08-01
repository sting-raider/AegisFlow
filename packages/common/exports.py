from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from typing import Any

FLOW_EXPORT_FIELDS = (
    "event_id",
    "timestamp_start",
    "timestamp_end",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "application_protocol",
    "direction",
    "duration_ms",
    "packets_forward",
    "packets_reverse",
    "bytes_forward",
    "bytes_reverse",
    "packet_rate",
    "byte_rate",
    "packet_length_mean",
    "packet_length_std",
    "iat_mean",
    "iat_std",
    "tcp_syn_count",
    "tcp_ack_count",
    "tcp_fin_count",
    "tcp_rst_count",
    "source_adapter",
    "feature_extractor_version",
)


def anonymize_ip(value: str, salt: bytes) -> str:
    digest = hmac.new(salt, value.encode(), hashlib.sha256).hexdigest()[:16]
    return f"ip_{digest}"


def sanitize_flow_export(
    payload: Mapping[str, Any], *, anonymize_ips: bool, salt: bytes
) -> dict[str, str | int | float | None]:
    result: dict[str, str | int | float | None] = {}
    for key in FLOW_EXPORT_FIELDS:
        value = payload.get(key)
        if isinstance(value, bool):
            continue
        if value is None or isinstance(value, str | int | float):
            result[key] = value
    if anonymize_ips:
        for key in ("src_ip", "dst_ip"):
            value = result.get(key)
            if isinstance(value, str):
                result[key] = anonymize_ip(value, salt)
    return result
