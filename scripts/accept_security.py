from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path
from typing import TypedDict


class SecurityAcceptanceError(RuntimeError):
    pass


class Category(TypedDict):
    name: str
    controls: list[str]
    paths: list[str]


CATEGORIES: list[Category] = [
    {
        "name": "identity_and_browser_boundary",
        "controls": [
            "RBAC bypass and role escalation",
            "malformed/oversized JWT and algorithm confusion",
            "unknown/malicious key ID refresh amplification",
            "oversized JWKS",
            "WebSocket authentication/origin/connection/frame bounds",
            "principal and path-scope rate limits",
            "CORS origin confusion",
        ],
        "paths": ["tests/unit/test_auth.py", "tests/integration/test_api.py"],
    },
    {
        "name": "exports_and_data_boundary",
        "controls": [
            "export authorization and raw-address privilege",
            "allow-listed/pseudonymized output",
            "spreadsheet-formula escaping",
            "retention dependency safety",
        ],
        "paths": ["tests/unit/test_exports.py", "tests/unit/test_retention.py"],
    },
    {
        "name": "model_and_artifact_governance",
        "controls": [
            "model promotion authorization",
            "creator/reviewer/promoter separation",
            "path containment and artifact replacement",
            "checksum/schema/order binding",
            "audited promotion and rollback",
        ],
        "paths": [
            "tests/unit/test_model_bundle.py",
            "tests/unit/test_model_governance.py",
            "tests/integration/test_model_governance_api.py",
        ],
    },
    {
        "name": "untrusted_input_and_queue_boundary",
        "controls": [
            "oversized stream records",
            "malformed/schema-invalid event quarantine",
            "hash-only dead letters",
            "bounded queue and recovery behavior",
        ],
        "paths": [
            "tests/unit/test_bus_recovery.py",
            "tests/unit/test_detector_worker.py",
            "tests/unit/test_consumer_recovery.py",
        ],
    },
    {
        "name": "optional_provider_boundary",
        "controls": [
            "remote HTTPS and local loopback-only provider configuration",
            "recursive endpoint/payload/secret removal",
            "prompt-injection data boundary",
            "active-response output rejection",
            "bounded retry/rate/output and deterministic fallback",
        ],
        "paths": ["tests/unit/test_explanations.py", "tests/unit/test_drift_explanations.py"],
    },
    {
        "name": "production_configuration_and_privilege",
        "controls": [
            "unsafe identity/secret/provider/datastore configuration",
            "read-only/non-root/capability deployment shape",
            "retention and backup ownership",
            "secret-file parsing",
        ],
        "paths": [
            "tests/unit/test_production_check.py",
            "tests/unit/test_compose_safety.py",
            "tests/unit/test_database_config.py",
        ],
    },
]


def _result_from_junit(path: Path) -> dict[str, int]:
    root = ET.parse(path).getroot()
    suite = root if root.tag == "testsuite" else root.find("testsuite")
    if suite is None:
        raise SecurityAcceptanceError("pytest JUnit report has no test suite")
    return {
        "tests": int(suite.attrib.get("tests", "0")),
        "failures": int(suite.attrib.get("failures", "0")),
        "errors": int(suite.attrib.get("errors", "0")),
        "skipped": int(suite.attrib.get("skipped", "0")),
    }


def run_acceptance(output: Path) -> dict[str, object]:
    started = datetime.now(UTC)
    results: list[dict[str, object]] = []
    failures: list[str] = []
    total_tests = 0
    with tempfile.TemporaryDirectory(prefix="aegisflow-security-") as temp_dir:
        for category in CATEGORIES:
            report_path = Path(temp_dir) / f"{category['name']}.xml"
            category_started = time.monotonic()
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    *category["paths"],
                    "--quiet",
                    f"--junitxml={report_path}",
                ],
                text=True,
                capture_output=True,
                check=False,
                timeout=300,
            )
            counts = _result_from_junit(report_path)
            total_tests += counts["tests"]
            passed = completed.returncode == 0 and counts["failures"] == counts["errors"] == 0
            if not passed:
                failures.append(f"security category failed: {category['name']}")
            results.append(
                {
                    "name": category["name"],
                    "controls": category["controls"],
                    "test_files": category["paths"],
                    "counts": counts,
                    "duration_seconds": time.monotonic() - category_started,
                    "passed": passed,
                }
            )
    report: dict[str, object] = {
        "schema_version": "1.0.0",
        "generated_at": started.isoformat(),
        "completed_at": datetime.now(UTC).isoformat(),
        "scope": "controlled local security acceptance fixtures",
        "safety": {
            "external_targets": False,
            "real_credentials": False,
            "packet_payloads_stored": False,
            "automatic_blocking": False,
        },
        "categories": results,
        "summary": {
            "categories": len(results),
            "tests": total_tests,
        },
        "verdict": {"passed": not failures, "failures": failures},
        "limitations": [
            "These controlled fixtures do not replace an organizational penetration test.",
            "Local Dex lifecycle evidence is retained separately in the OIDC acceptance report.",
            "Gateway, IdP, registry, managed service, and cluster policies require target "
            "validation.",
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if failures:
        raise SecurityAcceptanceError("; ".join(failures))
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Run controlled AegisFlow security acceptance")
    parser.add_argument(
        "--output", type=Path, default=Path("docs/acceptance/security-local.json")
    )
    args = parser.parse_args()
    try:
        report = run_acceptance(args.output)
    except (SecurityAcceptanceError, subprocess.TimeoutExpired) as exc:
        raise SystemExit(f"Security acceptance failed: {exc}") from exc
    print(json.dumps({"output": str(args.output), "verdict": report["verdict"]}))


if __name__ == "__main__":
    main()
