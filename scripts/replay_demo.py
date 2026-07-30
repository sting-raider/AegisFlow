from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from apps.api.database import Repository
from packages.contracts import Severity, SignatureEvent
from packages.detection import DetectionEngine
from packages.model_bundle import BundleError, load_production_bundle
from services.sensor import DemoAdapter, PcapAdapter
from training.cli.train_smoke import train


def replay(pcap: Path | None, database_url: str = "sqlite:///aegisflow-demo.db") -> dict[str, int]:
    registry = Path("models/registry")
    try:
        bundle = load_production_bundle(registry)
    except BundleError:
        train(registry)
        bundle = load_production_bundle(registry)
    engine = DetectionEngine(bundle)
    repository = Repository(database_url)
    repository.create_schema()
    adapter = PcapAdapter(pcap) if pcap else DemoAdapter()
    counts = {"flows": 0, "alerts": 0, "known_attack": 0, "suspicious_unknown": 0}
    for flow in adapter.flows():
        signature = None
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
        detection = engine.detect(flow, signature)
        counts["flows"] += 1
        if detection.verdict.value in counts:
            counts[detection.verdict.value] += 1
        if repository.ingest(flow, detection, signature):
            counts["alerts"] += 1
    return counts


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap", type=Path)
    parser.add_argument("--database-url", default="sqlite:///aegisflow-demo.db")
    args = parser.parse_args()
    counts = replay(args.pcap, args.database_url)
    print("Replay complete:", counts)


if __name__ == "__main__":
    main()
