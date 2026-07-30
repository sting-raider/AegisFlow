from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from packages.detection import DetectionEngine
from packages.features import FEATURE_NAMES
from packages.model_bundle import load_production_bundle
from services.sensor import DemoAdapter


def main() -> None:
    bundle = load_production_bundle(Path("models/registry"))
    engine = DetectionEngine(bundle)
    flows = list(DemoAdapter().flows())
    results = [engine.detect(flow) for flow in flows]
    compose = subprocess.run(
        ["docker", "compose", "-f", "compose.yml", "-f", "compose.demo.yml", "config", "--quiet"],
        capture_output=True,
        text=True,
        check=False,
    )
    report = {
        "python": sys.version.split()[0],
        "bundle": f"{bundle.manifest['model_name']}:{bundle.version}",
        "feature_count": len(FEATURE_NAMES),
        "demo_flows": len(flows),
        "demo_alerts": sum(result.final_risk_score >= 35 for result in results),
        "compose_config": "valid" if compose.returncode == 0 else "unavailable_or_invalid",
    }
    print(json.dumps(report, indent=2))
    if compose.returncode != 0:
        print(compose.stderr.strip(), file=sys.stderr)
        raise SystemExit(compose.returncode)


if __name__ == "__main__":
    main()
