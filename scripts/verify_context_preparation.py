"""Verify causal-context preparation provenance without evaluating a model."""

from __future__ import annotations

import argparse
import ipaddress
import math
import re
from pathlib import Path
from typing import Any

from packages.features.research import TEMPORAL_FEATURE_NAMES, TEMPORAL_SCHEMA_VERSION
from scripts.verify_registered_research_v2 import require, safe_aggregate
from training.v2.causal_context import (
    CAUSAL_SIDECAR_SCHEMA_VERSION,
    MULTIVIEW_SIDECAR_SCHEMA_VERSION,
)
from training.v2.provenance import read_object, sha256_file
from training.v2.tensors import load_records

MANIFEST_PATH = "docs/research-v2/preparation/context-sidecars-d3639a4.json"
MANIFEST_SHA256 = "31c52608689b46860a7c97c15847622c012084345c9178abe1c6169d07fe0f81"
SOURCE_MANIFEST_PATH = "docs/research-v2/preparation/prepared-pool-cba2329.json"
SOURCE_MANIFEST_SHA256 = "332939033261e67a41dd15f8c95edf54e4dd4fd1723e636c9e3c53f93c71f86a"
PREPARATION_COMMIT = "d3639a42071c1ef214d9c446f2ae2fe17605efff"
MULTIVIEW_MANIFEST_PATH = (
    "docs/research-v2/preparation/context-multiview-d87559a.json"
)
MULTIVIEW_MANIFEST_SHA256 = (
    "3e300cade95b3b3d992e0640035afcadfdcdb14db04b3a3da41c5d63b6dba78f"
)
MULTIVIEW_PREPARATION_COMMIT = "d87559ace70138fe5c418ce02653230fb11d990d"
SHA = re.compile(r"[0-9a-f]{64}")
SIDECAR_ENTRY_KEYS = {
    "event_id",
    "completion_index",
    "prior_completions",
    "coalesced_span_ms",
    "cold_start",
    "late_event",
    "vector",
}


def validate_manifest(
    root: Path, manifest: dict[str, Any], *, multiview: bool = False
) -> None:
    safe_aggregate(manifest)
    require(
        manifest["schema_version"] == "1.0.0"
        and manifest["permitted_use"] == "development_only",
        "context preparation is not development-only schema 1.0.0",
    )
    require(
        manifest["preparation_code_commit"]
        == (MULTIVIEW_PREPARATION_COMMIT if multiview else PREPARATION_COMMIT),
        "context preparation commit changed",
    )
    require(
        manifest["sidecar_schema_version"]
        == (
            MULTIVIEW_SIDECAR_SCHEMA_VERSION
            if multiview
            else CAUSAL_SIDECAR_SCHEMA_VERSION
        )
        and manifest["temporal_schema_version"] == TEMPORAL_SCHEMA_VERSION
        and manifest["temporal_feature_names"] == list(TEMPORAL_FEATURE_NAMES),
        "context feature contract changed",
    )
    require(
        manifest["history_order"] == "timestamp_end_timestamp_start_event_id",
        "context replay order changed",
    )
    source_manifest_path = root / SOURCE_MANIFEST_PATH
    require(
        sha256_file(source_manifest_path) == SOURCE_MANIFEST_SHA256
        == manifest["source_preparation"]["manifest_sha256"],
        "sealed source preparation hash changed",
    )
    source_manifest = read_object(source_manifest_path)
    source_entries = {entry["scenario"]: entry for entry in source_manifest["scenarios"]}
    scenarios = manifest["scenarios"]
    require(
        isinstance(scenarios, list)
        and len(scenarios) == len(source_entries) == 6,
        "context preparation scenario coverage changed",
    )
    observed: set[str] = set()
    sidecar_files: set[str] = set()
    sums = {
        "history_flows": 0,
        "emitted_rows": 0,
        "context_only_flows": 0,
        "cold_rows": 0,
        "late_rows": 0,
    }
    if multiview:
        sums.update({"non_causal_cold_rows": 0, "non_causal_late_rows": 0})
    for report in scenarios:
        require(isinstance(report, dict), "invalid context scenario report")
        scenario = report["scenario"]
        require(
            isinstance(scenario, str)
            and scenario in source_entries
            and scenario not in observed,
            "undeclared or duplicate context scenario",
        )
        observed.add(scenario)
        source = source_entries[scenario]
        require(
            report["source_hashes"]
            == {
                "pcap_sha256": source["pcap_sha256"],
                "labels_sha256": source["labels_sha256"],
                "sealed_rows_sha256": source["output_sha256"],
            },
            "context source binding differs from sealed preparation",
        )
        require(
            report["sealed_rows"] == report["emitted_rows"] == source["records"],
            "context emitted rows differ from sealed preparation",
        )
        for key in (
            "ambiguous_label_flows",
            "matched_unlabeled_flows",
            "flows_without_label_candidate",
        ):
            require(report[key] == source[key], f"context {key} accounting changed")
        require(
            report["adapter_flows"]
            == report["emitted_rows"] + report["context_only_flows"],
            "history-flow accounting mismatch",
        )
        require(
            report["context_only_flows"]
            == report["non_tcp_udp_icmp_flows"]
            + report["ambiguous_label_flows"]
            + report["matched_unlabeled_flows"]
            + report["flows_without_label_candidate"],
            "context-only flow accounting mismatch",
        )
        require(
            type(report["cold_rows"]) is int
            and 0 <= report["cold_rows"] <= report["emitted_rows"]
            and type(report["late_rows"]) is int
            and 0 <= report["late_rows"] <= report["emitted_rows"],
            "invalid cold/late context counts",
        )
        if multiview:
            require(
                type(report["non_causal_cold_rows"]) is int
                and 0 <= report["non_causal_cold_rows"] <= report["emitted_rows"]
                and type(report["non_causal_late_rows"]) is int
                and 0 <= report["non_causal_late_rows"] <= report["emitted_rows"],
                "invalid non-causal cold/late context counts",
            )
        require(
            all(SHA.fullmatch(report[key]) for key in ("ledger_sha256", "output_sha256")),
            "invalid context artifact hash",
        )
        expected_file = f"{scenario}.context.json"
        require(
            report["sidecar_file"] == expected_file
            and expected_file not in sidecar_files
            and type(report["sidecar_size_bytes"]) is int
            and report["sidecar_size_bytes"] > 0,
            "invalid or duplicate context sidecar declaration",
        )
        sidecar_files.add(expected_file)
        sums["history_flows"] += report["adapter_flows"]
        sums["emitted_rows"] += report["emitted_rows"]
        sums["context_only_flows"] += report["context_only_flows"]
        sums["cold_rows"] += report["cold_rows"]
        sums["late_rows"] += report["late_rows"]
        if multiview:
            sums["non_causal_cold_rows"] += report["non_causal_cold_rows"]
            sums["non_causal_late_rows"] += report["non_causal_late_rows"]
    require(observed == set(source_entries), "context scenarios are incomplete")
    require(manifest["totals"] == sums, "context preparation totals disagree")
    expected_totals = {
        "history_flows": 11_771,
        "emitted_rows": 7_145,
        "context_only_flows": 4_626,
        "cold_rows": 161,
        "late_rows": 0,
    }
    if multiview:
        expected_totals.update(
            {"non_causal_cold_rows": 0, "non_causal_late_rows": 7_133}
        )
    require(
        sums == expected_totals,
        "registered context preparation counts changed",
    )
    require(
        manifest["source_preparation"]["rows"] == 7_145
        and SHA.fullmatch(manifest["source_preparation"]["records_canonical_sha256"])
        is not None,
        "invalid context source-preparation summary",
    )


def _contains_ip_string(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_contains_ip_string(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_ip_string(item) for item in value)
    if isinstance(value, str):
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return False
        return True
    return False


def validate_local_sidecars(
    sidecar_directory: Path,
    prepared_manifest_path: Path,
    manifest: dict[str, Any],
    *,
    multiview: bool = False,
) -> None:
    prepared = read_object(prepared_manifest_path)
    require(
        sha256_file(prepared_manifest_path) == SOURCE_MANIFEST_SHA256,
        "local sealed preparation manifest differs from committed evidence",
    )
    prepared_entries = {entry["scenario"]: entry for entry in prepared["scenarios"]}
    declared = {report["sidecar_file"] for report in manifest["scenarios"]}
    actual = {path.name for path in sidecar_directory.glob("*.context.json")}
    require(actual == declared, "local context sidecar set differs from manifest")
    for report in manifest["scenarios"]:
        path = sidecar_directory / report["sidecar_file"]
        require(
            path.stat().st_size == report["sidecar_size_bytes"]
            and sha256_file(path) == report["output_sha256"],
            f"local sidecar hash/size mismatch: {path.name}",
        )
        payload = read_object(path)
        require(
            payload["schema_version"]
            == (
                MULTIVIEW_SIDECAR_SCHEMA_VERSION
                if multiview
                else CAUSAL_SIDECAR_SCHEMA_VERSION
            )
            and payload["temporal_schema_version"] == TEMPORAL_SCHEMA_VERSION
            and payload["temporal_feature_names"] == list(TEMPORAL_FEATURE_NAMES),
            "local sidecar feature contract mismatch",
        )
        require(
            payload["scenario"] == report["scenario"]
            and payload["source_hashes"] == report["source_hashes"]
            and payload["ledger_sha256"] == report["ledger_sha256"]
            and payload["history_flow_count"] == report["adapter_flows"]
            and payload["emitted_count"] == report["emitted_rows"],
            "local sidecar summary differs from manifest",
        )
        entries = payload["entries"]
        require(
            isinstance(entries, list) and len(entries) == report["emitted_rows"],
            "local sidecar row count mismatch",
        )
        event_ids: list[str] = []
        completion_indices: list[int] = []
        terminal_cold = terminal_late = 0
        for entry in entries:
            expected_keys = SIDECAR_ENTRY_KEYS | (
                {"non_causal_terminal_vector"} if multiview else set()
            )
            require(
                isinstance(entry, dict) and set(entry) == expected_keys,
                "local sidecar row schema changed",
            )
            vector = entry["vector"]
            require(
                isinstance(vector, list)
                and len(vector) == len(TEMPORAL_FEATURE_NAMES)
                and all(type(value) in {int, float} and math.isfinite(value) for value in vector),
                "local sidecar contains an invalid temporal vector",
            )
            if multiview:
                terminal_vector = entry["non_causal_terminal_vector"]
                require(
                    isinstance(terminal_vector, list)
                    and len(terminal_vector) == len(TEMPORAL_FEATURE_NAMES)
                    and all(
                        type(value) in {int, float} and math.isfinite(value)
                        for value in terminal_vector
                    ),
                    "local sidecar contains an invalid terminal vector",
                )
                terminal_cold += int(
                    terminal_vector[TEMPORAL_FEATURE_NAMES.index("temporal_cold_start")]
                )
                terminal_late += int(
                    terminal_vector[TEMPORAL_FEATURE_NAMES.index("temporal_late_event")]
                )
            require(
                type(entry["completion_index"]) is int
                and entry["completion_index"] >= 0
                and entry["prior_completions"] == entry["completion_index"]
                and type(entry["coalesced_span_ms"]) in {int, float}
                and math.isfinite(entry["coalesced_span_ms"])
                and entry["coalesced_span_ms"] >= 0
                and type(entry["cold_start"]) is bool
                and type(entry["late_event"]) is bool,
                "local sidecar audit fields are invalid",
            )
            event_ids.append(entry["event_id"])
            completion_indices.append(entry["completion_index"])
        require(len(event_ids) == len(set(event_ids)), "duplicate local sidecar event ID")
        require(
            completion_indices == sorted(completion_indices),
            "sidecar completion order changed",
        )
        scenario = report["scenario"]
        sealed_path = prepared_manifest_path.parent / prepared_entries[scenario]["prepared_file"]
        sealed_ids = {record["event_id"] for record in load_records([sealed_path])}
        require(set(event_ids) == sealed_ids, "local sidecar rows differ from sealed cohort")
        if multiview:
            reference = payload["non_causal_reference"]
            require(
                reference
                == {
                    "kind": "read_only_terminal_retained_state",
                    "deployable": False,
                    "cold_count": report["non_causal_cold_rows"],
                    "late_count": report["non_causal_late_rows"],
                }
                and terminal_cold == report["non_causal_cold_rows"]
                and terminal_late == report["non_causal_late_rows"],
                "local terminal-reference summary differs from vectors",
            )
        require(not _contains_ip_string(payload), "local sidecar persists an IP address string")
        require(
            not ({"timestamp", "source_ip", "destination_ip", "sensor_id"} & set(payload)),
            "local sidecar persists a forbidden top-level field",
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sidecar-dir", type=Path)
    parser.add_argument("--prepared-manifest", type=Path)
    parser.add_argument(
        "--multiview",
        action="store_true",
        help="validate local sidecars against the multiview evidence",
    )
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    manifest_path = root / MANIFEST_PATH
    require(sha256_file(manifest_path) == MANIFEST_SHA256, "context manifest bytes changed")
    manifest = read_object(manifest_path)
    validate_manifest(root, manifest)
    multiview_manifest_path = root / MULTIVIEW_MANIFEST_PATH
    require(
        sha256_file(multiview_manifest_path) == MULTIVIEW_MANIFEST_SHA256,
        "multiview context manifest bytes changed",
    )
    multiview_manifest = read_object(multiview_manifest_path)
    validate_manifest(root, multiview_manifest, multiview=True)
    require(
        (args.sidecar_dir is None) == (args.prepared_manifest is None),
        "local verification requires both --sidecar-dir and --prepared-manifest",
    )
    if args.sidecar_dir is not None and args.prepared_manifest is not None:
        validate_local_sidecars(
            args.sidecar_dir,
            args.prepared_manifest,
            multiview_manifest if args.multiview else manifest,
            multiview=args.multiview,
        )
    print(
        "verified causal and multiview context preparation: 6 scenarios, "
        "11771 history flows, 7145 sealed rows; development only"
    )


if __name__ == "__main__":
    main()
