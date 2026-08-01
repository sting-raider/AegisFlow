from __future__ import annotations

import argparse
import hashlib
import os
import time
from collections.abc import Iterable
from pathlib import Path
from uuid import NAMESPACE_URL, UUID, uuid5

from packages.common import log_event, service_logger
from packages.common.bus import RedisStreamBus
from packages.contracts import FlowEvent, Severity, SignatureEvent
from packages.detection.suricata import EveJsonReader, EveReadBatch, correlate_eve_event
from services.sensor.adapters import (
    DemoAdapter,
    LiveAdapter,
    NfstreamAdapter,
    PcapAdapter,
    SensorAdapter,
)

FLOW_STREAM = "aegisflow:flows"
MAX_EVE_FILE_BYTES = 256 * 1024 * 1024
LOGGER = service_logger("sensor")


def load_eve_file(path: Path) -> EveReadBatch:
    resolved = path.resolve()
    if not resolved.is_file():
        raise FileNotFoundError(resolved)
    if resolved.stat().st_size > MAX_EVE_FILE_BYTES:
        raise ValueError("EVE file exceeds the 256 MiB offline safety limit")
    reader = EveJsonReader()
    return reader.feed(resolved.read_bytes(), final=True)


def correlate_signatures(flows: list[FlowEvent], batch: EveReadBatch) -> dict[UUID, SignatureEvent]:
    severity_order = {
        Severity.INFORMATIONAL: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }
    correlated: dict[UUID, SignatureEvent] = {}
    for event in batch.events:
        if not isinstance(event, SignatureEvent):
            continue
        flow = correlate_eve_event(event, flows)
        if flow is None:
            continue
        previous = correlated.get(flow.event_id)
        if previous is None or severity_order[event.severity] > severity_order[previous.severity]:
            correlated[flow.event_id] = event
    return correlated


def run() -> None:
    parser = argparse.ArgumentParser(description="Publish validated AegisFlow flows")
    parser.add_argument("--mode", choices=["demo", "pcap", "live"], default="demo")
    parser.add_argument("--pcap", type=Path)
    parser.add_argument("--interface")
    parser.add_argument("--adapter", choices=["scapy", "nfstream"], default="scapy")
    parser.add_argument(
        "--eve", type=Path, help="bounded Suricata EVE JSON for offline correlation"
    )
    args = parser.parse_args()
    adapter: SensorAdapter
    if args.mode == "pcap":
        if args.pcap is None:
            parser.error("--pcap is required in pcap mode")
        adapter = (
            NfstreamAdapter(args.pcap) if args.adapter == "nfstream" else PcapAdapter(args.pcap)
        )
    elif args.mode == "live":
        if args.eve is not None:
            parser.error("--eve snapshot correlation is available only in demo/PCAP mode")
        log_event(LOGGER, "live_capture_privacy_warning", level="warning")
        adapter = LiveAdapter(args.interface)
    else:
        adapter = DemoAdapter()
    bus = RedisStreamBus(
        os.getenv("AEGISFLOW_REDIS_URL", "redis://localhost:6379/0"),
        maxlen=int(os.getenv("AEGISFLOW_STREAM_MAXLEN", "100000")),
        max_payload_bytes=int(os.getenv("AEGISFLOW_STREAM_MAX_PAYLOAD_BYTES", "1048576")),
        on_backpressure=lambda stream: log_event(
            LOGGER, "queue_capacity_pressure", level="warning", error_code=stream
        ),
    )
    flow_source: Iterable[FlowEvent] = adapter.flows()
    correlated: dict[UUID, SignatureEvent] = {}
    if args.eve is not None:
        buffered_flows = list(flow_source)
        batch = load_eve_file(args.eve)
        for error in batch.errors:
            log_event(
                LOGGER,
                "suricata_processing_error",
                level="error",
                error_code=error.error,
            )
        correlated = correlate_signatures(buffered_flows, batch)
        log_event(LOGGER, "suricata_eve_summary")
        flow_source = buffered_flows
    for flow in flow_source:
        envelope: dict[str, object] = {"flow": flow.model_dump(mode="json")}
        signature = correlated.get(flow.event_id)
        if signature is None and flow.protocol_metadata.get("scenario") == "known-signature":
            raw = b"aegisflow-safe-demo-signature"
            signature = SignatureEvent(
                event_id=uuid5(NAMESPACE_URL, "aegisflow-demo-signature"),
                timestamp=flow.timestamp_start,
                community_flow_id=flow.community_flow_id,
                signature_id="9000001",
                signature_name="AEGISFLOW DEMO repeated authentication pattern",
                category="Attempted Administrator Privilege Gain",
                severity=Severity.HIGH,
                source="fixture",
                raw_event_hash=hashlib.sha256(raw).hexdigest(),
                metadata={"fixture": True},
            )
        if signature is not None:
            envelope["signature"] = signature.model_dump(mode="json")
        bus.publish(FLOW_STREAM, envelope)
        log_event(LOGGER, "flow_published", flow_id=str(flow.event_id))
        if args.mode == "demo":
            time.sleep(0.15)


if __name__ == "__main__":
    run()
