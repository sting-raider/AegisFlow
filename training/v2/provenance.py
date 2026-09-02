"""Reproducible preparation and partition provenance for corrected v2 experiments.

Raw captures and prepared rows remain local. Committable manifests contain only
hashes, aggregate counts, public scenario names and execution/environment metadata.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import platform
import re
import subprocess
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Any, cast

from training.data.development import frozen_source_hashes
from training.v2.prepare_sequences import prepare_scenario
from training.v2.tensors import SequenceRecord, load_records

_SHA256 = re.compile(r"[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_SCENARIO = re.compile(r"CTU-(?:IoT-Malware|Honeypot)-Capture-\d+-\d+")
_SOURCE_ROOT = Path(__file__).resolve().parents[2]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def read_object(path: Path) -> dict[str, Any]:
    decoded = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(decoded, dict):
        raise ValueError(f"expected JSON object: {path.name}")
    return cast(dict[str, Any], decoded)


def write_new_json(path: Path, value: object) -> None:
    content = json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(content)


def clean_execution_commit(root: Path) -> str:
    """Require all executed project modules to come from this clean checkout."""
    if root.resolve() != _SOURCE_ROOT:
        raise ValueError("execution root differs from imported project source")
    status = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=root, check=True, capture_output=True, text=True,
    ).stdout.strip()
    if status:
        raise ValueError("registered research requires a clean committed worktree")
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True,
    ).stdout.strip()


def _basename(directory: Path, name: Any) -> Path:
    if (
        not isinstance(name, str) or not name or name in {".", ".."}
        or any(character in name for character in "/\\:")
    ):
        raise ValueError("source filename must be a basename")
    path = directory / name
    if path.resolve().parent != directory.resolve():
        raise ValueError("source filename escapes its evidence directory")
    return path


def verify_capture_pool(
    root: Path, pcap_directory: Path,
) -> tuple[dict[str, Any], dict[str, tuple[Path, Path]]]:
    """Verify all pinned capture/label bytes before any replay begins."""
    pool = read_object(root / "configs/research-v2/pool-hashes.json")
    frozen = frozen_source_hashes(root / "configs/evaluation/frozen-evidence-v1.json")
    if not pool:
        raise ValueError("empty development capture pool")
    sources: dict[str, tuple[Path, Path]] = {}
    for scenario, entry in pool.items():
        if not _SCENARIO.fullmatch(scenario) or not isinstance(entry, dict):
            raise ValueError("invalid development scenario")
        pcap_hash, labels_hash = entry.get("pcap_sha256"), entry.get("labels_sha256")
        if any(not isinstance(h, str) or not _SHA256.fullmatch(h)
               for h in (pcap_hash, labels_hash)):
            raise ValueError(f"invalid source hash for {scenario}")
        if pcap_hash in frozen or labels_hash in frozen:
            raise ValueError(f"frozen-final source refused: {scenario}")
        manifest = read_object(pcap_directory / f"{scenario}.manifest.json")
        if manifest.get("scenario") != scenario:
            raise ValueError(f"capture manifest scenario mismatch: {scenario}")
        pcap = _basename(pcap_directory, manifest.get("pcap_filename"))
        labels = _basename(pcap_directory, f"{scenario}.conn.log.labeled")
        if pcap.stat().st_size != entry.get("pcap_size_bytes"):
            raise ValueError(f"capture size mismatch: {scenario}")
        if sha256_file(pcap) != pcap_hash or sha256_file(labels) != labels_hash:
            raise ValueError(f"capture/label hash mismatch: {scenario}")
        sources[scenario] = (pcap, labels)
    return pool, sources


def prepare_verified_pool(root: Path, pcap_directory: Path, output_directory: Path) -> Path:
    if output_directory.exists():
        raise FileExistsError("refusing to reuse a preparation evidence directory")
    commit = clean_execution_commit(root)
    pool, sources = verify_capture_pool(root, pcap_directory)
    started_at = datetime.now(UTC).isoformat()
    started = perf_counter()
    output_directory.mkdir(parents=True, exist_ok=False)
    reports: list[dict[str, Any]] = []
    for scenario in sorted(pool):
        destination = output_directory / f"{scenario}.jsonl"
        report = prepare_scenario(scenario, pcap_directory, destination)
        pcap, labels = sources[scenario]
        report.update({
            "pcap_sha256": pool[scenario]["pcap_sha256"],
            "labels_sha256": pool[scenario]["labels_sha256"],
            "pcap_size_bytes": pcap.stat().st_size,
            "labels_size_bytes": labels.stat().st_size,
            "prepared_file": destination.name,
            "prepared_size_bytes": destination.stat().st_size,
        })
        reports.append(report)
        print(f"prepared {scenario}: {report['records']} rows; "
              f"{report['ambiguous_label_flows']} ambiguous joins excluded", flush=True)
    # Catch concurrent source or code changes. Partial outputs are kept as an
    # explicitly incomplete attempt; no success manifest is written on failure.
    final_pool, _ = verify_capture_pool(root, pcap_directory)
    if final_pool != pool or clean_execution_commit(root) != commit:
        raise ValueError("preparation inputs changed during execution")
    manifest_path = output_directory / "preparation-manifest.json"
    write_new_json(manifest_path, {
        "schema_version": "2.0.0",
        "permitted_use": "development_only",
        "preparation_code_commit": commit,
        "started_at": started_at,
        "completed_at": datetime.now(UTC).isoformat(),
        "elapsed_seconds": perf_counter() - started,
        "source_pool_sha256_canonical": canonical_digest(pool),
        "sequence_capacity": 20,
        "join_policy": "unordered_endpoints_protocol_interval_gap_le_1s_reject_conflicting_ties",
        "environment": {
            "python": platform.python_version(),
            "platform": platform.system(),
            "machine": platform.machine(),
            "scapy": importlib.metadata.version("scapy"),
        },
        "scenarios": reports,
        "limitations": [
            "PCAP adapter coalesces each canonical five-tuple over the capture.",
            "Unmatched and ambiguously labelled flows are excluded and counted.",
            "Public ground-truth labels are research labels, not site operator approval.",
            "Only derived metadata is emitted; payload contents and addresses are not stored.",
        ],
    })
    return manifest_path


def load_verified_preparation(root: Path, manifest_path: Path) -> list[SequenceRecord]:
    manifest = read_object(manifest_path)
    pool = read_object(root / "configs/research-v2/pool-hashes.json")
    if (manifest.get("schema_version") != "2.0.0"
            or manifest.get("permitted_use") != "development_only"):
        raise ValueError("unsupported or non-development preparation manifest")
    if not _COMMIT.fullmatch(str(manifest.get("preparation_code_commit", ""))):
        raise ValueError("preparation execution commit is missing")
    if manifest.get("source_pool_sha256_canonical") != canonical_digest(pool):
        raise ValueError("preparation pool binding changed")
    entries = manifest.get("scenarios")
    if not isinstance(entries, list) or len(entries) != len(pool):
        raise ValueError("preparation scenario manifest is incomplete")
    frozen = frozen_source_hashes(root / "configs/evaluation/frozen-evidence-v1.json")
    seen: set[str] = set()
    all_records: list[SequenceRecord] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("invalid preparation scenario entry")
        scenario = entry.get("scenario")
        if not isinstance(scenario, str) or scenario not in pool or scenario in seen:
            raise ValueError("undeclared or duplicate preparation scenario")
        seen.add(scenario)
        for key in ("pcap_sha256", "labels_sha256"):
            if entry.get(key) != pool[scenario][key] or entry.get(key) in frozen:
                raise ValueError("preparation source binding changed or frozen source used")
        expected_name = f"{scenario}.jsonl"
        if entry.get("prepared_file") != expected_name:
            raise ValueError("prepared filename does not match declared scenario")
        path = _basename(manifest_path.parent, expected_name)
        if (sha256_file(path) != entry.get("output_sha256")
                or path.stat().st_size != entry.get("prepared_size_bytes")):
            raise ValueError(f"prepared file hash/size mismatch: {scenario}")
        records = load_records([path])
        if not records or len(records) != entry.get("records"):
            raise ValueError(f"prepared row count mismatch: {scenario}")
        if any(record.get("scenario") != scenario for record in records):
            raise ValueError(f"prepared record scenario mismatch: {scenario}")
        all_records.extend(records)
    actual = {path.name for path in manifest_path.parent.glob("*.jsonl")}
    if actual != {f"{scenario}.jsonl" for scenario in seen}:
        raise ValueError("unbound prepared files in evidence directory")
    return all_records


def partition_provenance(records: Sequence[SequenceRecord]) -> dict[str, object]:
    """Aggregate, reproducible identity/content binding; no per-row IDs are emitted."""
    from collections import Counter

    ordered = sorted(records, key=lambda record: record["event_id"])
    return {
        "rows": len(ordered),
        "event_ids_sha256": canonical_digest([record["event_id"] for record in ordered]),
        "records_sha256": canonical_digest(ordered),
        "scenarios": sorted({record["scenario"] for record in ordered}),
        "families": dict(sorted(Counter(record["family"] for record in ordered).items())),
        "binary_labels": dict(
            sorted(Counter(record["binary_label"] for record in ordered).items())
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prepare v2 data with clean-code/source provenance"
    )
    parser.add_argument("--pcap-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    result = prepare_verified_pool(Path.cwd(), args.pcap_dir, args.output_dir)
    print(f"preparation manifest: {result.name}; sha256={sha256_file(result)}")


if __name__ == "__main__":
    main()
