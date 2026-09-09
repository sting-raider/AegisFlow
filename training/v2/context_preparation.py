"""Prepare immutable causal-context sidecars for DEV2-CONTEXT-001."""

from __future__ import annotations

import argparse
import importlib.metadata
import platform
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Any

from packages.features.research import TEMPORAL_FEATURE_NAMES, TEMPORAL_SCHEMA_VERSION
from training.v2.causal_context import (
    MULTIVIEW_SIDECAR_SCHEMA_VERSION,
    build_scenario_sidecar,
)
from training.v2.provenance import (
    canonical_digest,
    clean_execution_commit,
    load_verified_preparation,
    read_object,
    sha256_file,
    verify_capture_pool,
    write_new_json,
)

ROOT = Path(__file__).resolve().parents[2]


def prepare_context_sidecars(
    root: Path,
    prepared_manifest_path: Path,
    pcap_directory: Path,
    output_directory: Path,
) -> Path:
    """Create all six sidecars from clean code and verified development inputs."""
    if output_directory.exists():
        raise FileExistsError("refusing to reuse a causal-context preparation directory")
    commit = clean_execution_commit(root)
    pool, _ = verify_capture_pool(root, pcap_directory)
    prepared_manifest = read_object(prepared_manifest_path)
    prepared_records = load_verified_preparation(root, prepared_manifest_path)
    prepared_digest = canonical_digest(prepared_records)
    entries = prepared_manifest.get("scenarios")
    if not isinstance(entries, list):
        raise ValueError("causal-context preparation requires scenario entries")
    prepared_by_scenario: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("scenario"), str):
            raise ValueError("invalid prepared scenario entry")
        scenario = str(entry["scenario"])
        if scenario in prepared_by_scenario:
            raise ValueError("duplicate prepared scenario entry")
        prepared_by_scenario[scenario] = entry
    if set(prepared_by_scenario) != set(pool):
        raise ValueError("prepared scenarios differ from the verified capture pool")

    started_at = datetime.now(UTC).isoformat()
    started = perf_counter()
    output_directory.mkdir(parents=True, exist_ok=False)
    reports: list[dict[str, Any]] = []
    for scenario in sorted(pool):
        entry = prepared_by_scenario[scenario]
        sequences_path = prepared_manifest_path.parent / f"{scenario}.jsonl"
        destination = output_directory / f"{scenario}.context.json"
        report = build_scenario_sidecar(
            scenario,
            pcap_directory,
            sequences_path,
            destination,
        )
        expected = {
            "emitted_rows": entry.get("records"),
            "sealed_rows": entry.get("records"),
            "ambiguous_label_flows": entry.get("ambiguous_label_flows"),
            "matched_unlabeled_flows": entry.get("matched_unlabeled_flows"),
            "flows_without_label_candidate": entry.get("flows_without_label_candidate"),
        }
        if any(report[key] != value for key, value in expected.items()):
            raise ValueError(f"scenario {scenario} accounting differs from sealed preparation")
        expected_hashes = {
            "pcap_sha256": pool[scenario]["pcap_sha256"],
            "labels_sha256": pool[scenario]["labels_sha256"],
            "sealed_rows_sha256": entry["output_sha256"],
        }
        if report["source_hashes"] != expected_hashes:
            raise ValueError(f"scenario {scenario} source hashes differ from preparation")
        report.update(
            {
                "sidecar_file": destination.name,
                "sidecar_size_bytes": destination.stat().st_size,
            }
        )
        reports.append(report)
        print(
            f"prepared {scenario}: {report['emitted_rows']} emitted / "
            f"{report['adapter_flows']} history flows",
            flush=True,
        )

    final_pool, _ = verify_capture_pool(root, pcap_directory)
    final_records = load_verified_preparation(root, prepared_manifest_path)
    if (
        final_pool != pool
        or canonical_digest(final_records) != prepared_digest
        or clean_execution_commit(root) != commit
    ):
        raise ValueError("causal-context code or inputs changed during preparation")
    manifest_path = output_directory / "context-preparation-manifest.json"
    write_new_json(
        manifest_path,
        {
            "schema_version": "1.0.0",
            "permitted_use": "development_only",
            "preparation_code_commit": commit,
            "started_at": started_at,
            "completed_at": datetime.now(UTC).isoformat(),
            "elapsed_seconds": perf_counter() - started,
            "source_preparation": {
                "manifest_sha256": sha256_file(prepared_manifest_path),
                "records_canonical_sha256": prepared_digest,
                "rows": len(prepared_records),
            },
            "sidecar_schema_version": MULTIVIEW_SIDECAR_SCHEMA_VERSION,
            "temporal_schema_version": TEMPORAL_SCHEMA_VERSION,
            "temporal_feature_names": list(TEMPORAL_FEATURE_NAMES),
            "history_order": "timestamp_end_timestamp_start_event_id",
            "scenarios": reports,
            "totals": {
                "history_flows": sum(int(report["adapter_flows"]) for report in reports),
                "emitted_rows": sum(int(report["emitted_rows"]) for report in reports),
                "context_only_flows": sum(
                    int(report["context_only_flows"]) for report in reports
                ),
                "cold_rows": sum(int(report["cold_rows"]) for report in reports),
                "late_rows": sum(int(report["late_rows"]) for report in reports),
                "non_causal_cold_rows": sum(
                    int(report["non_causal_cold_rows"]) for report in reports
                ),
                "non_causal_late_rows": sum(
                    int(report["non_causal_late_rows"]) for report in reports
                ),
            },
            "environment": {
                "python": platform.python_version(),
                "platform": platform.system(),
                "machine": platform.machine(),
                "scapy": importlib.metadata.version("scapy"),
            },
            "limitations": [
                "PcapAdapter coalesces each canonical five-tuple over the capture.",
                "Completion-ordered context cannot recover within-flow packet chronology.",
                "Public labels are research labels, not deployed operator approval.",
                "Only derived vectors, event IDs and aggregate audit fields are persisted.",
                "No frozen-final source, model fitting or candidate selection is permitted.",
            ],
        },
    )
    return manifest_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared-manifest", required=True, type=Path)
    parser.add_argument("--pcap-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    result = prepare_context_sidecars(
        ROOT,
        args.prepared_manifest,
        args.pcap_dir,
        args.output_dir,
    )
    print(f"context preparation manifest: {result}; sha256={sha256_file(result)}")


if __name__ == "__main__":
    main()
