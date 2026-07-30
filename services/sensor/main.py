from __future__ import annotations

import argparse
import hashlib
import os
import time
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from packages.common.bus import RedisStreamBus
from packages.contracts import Severity, SignatureEvent
from services.sensor.adapters import DemoAdapter, LiveAdapter, PcapAdapter, SensorAdapter

FLOW_STREAM = "aegisflow:flows"


def run() -> None:
    parser = argparse.ArgumentParser(description="Publish validated AegisFlow flows")
    parser.add_argument("--mode", choices=["demo", "pcap", "live"], default="demo")
    parser.add_argument("--pcap", type=Path)
    parser.add_argument("--interface")
    args = parser.parse_args()
    adapter: SensorAdapter
    if args.mode == "pcap":
        if args.pcap is None:
            parser.error("--pcap is required in pcap mode")
        adapter = PcapAdapter(args.pcap)
    elif args.mode == "live":
        print(
            "PRIVACY WARNING: live capture requires authorization for the explicit "
            "local interface; "
            "packet payloads are not persisted."
        )
        adapter = LiveAdapter(args.interface)
    else:
        adapter = DemoAdapter()
    bus = RedisStreamBus(os.getenv("AEGISFLOW_REDIS_URL", "redis://localhost:6379/0"))
    for flow in adapter.flows():
        envelope: dict[str, object] = {"flow": flow.model_dump(mode="json")}
        if flow.protocol_metadata.get("scenario") == "known-signature":
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
            envelope["signature"] = signature.model_dump(mode="json")
        bus.publish(FLOW_STREAM, envelope)
        print(f"published {flow.event_id} {flow.protocol_metadata.get('scenario', '')}")
        if args.mode == "demo":
            time.sleep(0.15)


if __name__ == "__main__":
    run()
