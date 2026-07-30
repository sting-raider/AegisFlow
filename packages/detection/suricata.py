from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

from packages.contracts import Severity, SignatureEvent

MAX_EVE_LINE_BYTES = 1024 * 1024


class EveParseError(ValueError):
    pass


def parse_eve_line(line: bytes | str) -> SignatureEvent | None:
    raw = line.encode() if isinstance(line, str) else line
    if len(raw) > MAX_EVE_LINE_BYTES:
        raise EveParseError("EVE line exceeds 1 MiB")
    try:
        event: dict[str, Any] = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise EveParseError("malformed or partially written EVE JSON") from exc
    if event.get("event_type") != "alert":
        return None
    alert = event.get("alert")
    if not isinstance(alert, dict):
        raise EveParseError("alert event is missing structured alert metadata")
    try:
        severity_number = int(alert.get("severity", 3))
        severity = {
            1: Severity.CRITICAL,
            2: Severity.HIGH,
            3: Severity.MEDIUM,
        }.get(severity_number, Severity.LOW)
        return SignatureEvent(
            timestamp=datetime.fromisoformat(str(event["timestamp"]).replace("Z", "+00:00")),
            community_flow_id=str(event.get("community_id") or event.get("flow_id")),
            signature_id=str(alert["signature_id"]),
            signature_name=str(alert["signature"]),
            category=str(alert.get("category", "unknown")),
            severity=severity,
            source="suricata",
            raw_event_hash=hashlib.sha256(raw).hexdigest(),
            metadata={
                key: value
                for key, value in {
                    "src_ip": event.get("src_ip"),
                    "src_port": event.get("src_port"),
                    "dest_ip": event.get("dest_ip"),
                    "dest_port": event.get("dest_port"),
                    "proto": event.get("proto"),
                }.items()
                if isinstance(value, str | int | float | bool)
            },
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise EveParseError("incomplete EVE alert") from exc
