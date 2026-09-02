"""Fail-closed integrity checks for Detector-v2 development evidence.

This is archive integrity, NOT scientific validation or candidate acceptance.
Historical reports lack complete run provenance and have known partition defects.
The retrospective policy and source manifest are bound alongside aggregate JSON
reports and row-level embedding archives; final data remains sealed.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, cast

import numpy as np

from training.data.development import frozen_source_hashes

_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_EXPERIMENT_SCHEMA = "1.0.0"
_PERMITTED_STATUS = {
    "development_diagnostic_no_candidate_selected",
    "development_evidence_only_no_candidate_selected",
}
_PROHIBITED_KEY_PARTS = {
    "destination_ip",
    "dst_ip",
    "packet_payload",
    "password",
    "payload",
    "prediction",
    "secret",
    "source_ip",
    "src_ip",
    "token",
}
_NPZ_KEYS = {"embeddings", "binary_label", "scenario", "family"}
_ARCHIVE_NAMESPACE = "docs/research-v2/experiments"
_FROZEN_MANIFEST = "configs/evaluation/frozen-evidence-v1.json"
_ARCHIVE_FAMILIES = {"benign", "c_and_c", "ddos", "port_scan"}


@dataclass(frozen=True)
class ResearchV2Summary:
    """Counts returned after the complete v2 evidence boundary is verified."""

    experiments_verified: int
    artifacts_verified: int
    prepared_scenarios_verified: int
    publication_commit: str
    scientific_status: str = "historical_unvalidated"


def _sha256(path: Path) -> str:
    if path.suffix == ".json":
        # Only Git checkout line endings are normalized. Preserve BOM, whitespace,
        # key order, and all other bytes so semantic/cosmetic tampering is detected.
        content = path.read_bytes()
        content.decode("utf-8-sig")
        return hashlib.sha256(content.replace(b"\r\n", b"\n")).hexdigest()
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_object(path: Path) -> dict[str, Any]:
    try:
        # ``pool-hashes.json`` is an existing UTF-8-with-BOM manifest; accepting
        # that encoding keeps the verifier read-only without dropping its BOM hash.
        decoded = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid JSON evidence: {path}") from error
    if not isinstance(decoded, dict):
        raise ValueError(f"evidence must be a JSON object: {path}")
    return cast(dict[str, Any], decoded)


def _safe_path(root: Path, relative: str) -> Path:
    if (
        not relative
        or "\\" in relative
        or ":" in relative
        or any(part in {"", ".", ".."} for part in relative.split("/"))
        or PurePosixPath(relative).is_absolute()
        or relative.split("/")[0] not in {"configs", "docs"}
    ):
        raise ValueError(f"invalid research-v2 repository path: {relative}")
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise ValueError(f"research-v2 artifact escapes repository: {relative}") from error
    return candidate


def _require_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"invalid SHA-256 for {label}")
    return value


def _require_relative_hash(root: Path, relative: Any, expected: Any, label: str) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise ValueError(f"invalid path for {label}")
    digest = _require_sha(expected, label)
    path = _safe_path(root, relative)
    if not path.is_file():
        raise ValueError(f"missing research-v2 artifact: {relative}")
    if _sha256(path) != digest:
        raise ValueError(f"research-v2 artifact hash mismatch: {relative}")
    return path


def _reject_sensitive_keys(value: Any, location: str = "report") -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = str(key).lower().replace("-", "_")
            if any(part in normalized for part in _PROHIBITED_KEY_PARTS):
                raise ValueError(f"research-v2 report contains prohibited key: {location}.{key}")
            _reject_sensitive_keys(nested, f"{location}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _reject_sensitive_keys(nested, f"{location}[{index}]")


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [item for nested in value.values() for item in _strings(nested)]
    if isinstance(value, list):
        return [item for nested in value for item in _strings(nested)]
    return []


def _validate_protocol(protocol: dict[str, Any]) -> tuple[set[str], set[str], set[str]]:
    if protocol.get("schema_version") != "1.0.0":
        raise ValueError("research-v2 protocol schema is unsupported")
    if protocol.get("phase") != "detector-v2":
        raise ValueError("research-v2 protocol phase is invalid")
    if protocol.get("permitted_use") != "development_only":
        raise ValueError("research-v2 protocol must be development-only")
    if (
        protocol.get("registration_kind") != "retrospective_archive_policy"
        or protocol.get("recorded_at") != "2026-09-02"
        or "declared_at" in protocol
    ):
        raise ValueError("research-v2 archive policy must not imply prospective registration")
    if protocol.get("seed") != 20260822:
        raise ValueError("research-v2 protocol seed changed")

    development = protocol.get("development_scenarios")
    prepared = protocol.get("prepared_scenarios")
    experiment_ids = protocol.get("experiment_ids")
    if not isinstance(development, list) or not all(isinstance(item, str) for item in development):
        raise ValueError("research-v2 development scenarios are invalid")
    if not isinstance(prepared, list) or not all(isinstance(item, str) for item in prepared):
        raise ValueError("research-v2 prepared scenarios are invalid")
    if not isinstance(experiment_ids, list) or not all(
        isinstance(item, str) for item in experiment_ids
    ):
        raise ValueError("research-v2 experiment IDs are invalid")
    development_set = set(cast(list[str], development))
    prepared_set = set(cast(list[str], prepared))
    experiment_set = set(cast(list[str], experiment_ids))
    if not prepared_set or not prepared_set <= development_set:
        raise ValueError("prepared scenarios must be a nonempty declared subset")
    if len(experiment_set) != len(experiment_ids):
        raise ValueError("research-v2 experiment IDs must be unique")

    reserved = protocol.get("reserved_final_environment")
    if not isinstance(reserved, dict):
        raise ValueError("reserved final environment is missing")
    if reserved.get("scenario") != "CTU-13 scenario 8" or reserved.get("family") != "rbot":
        raise ValueError("reserved final environment changed")
    if reserved.get("status") != "sealed":
        raise ValueError("reserved final environment must remain sealed")
    if reserved.get("maximum_runs_per_locked_candidate") != 1:
        raise ValueError("reserved final environment run limit changed")
    if reserved["scenario"] in development_set or reserved["scenario"] in prepared_set:
        raise ValueError("reserved final environment appears in development data")

    origin = protocol.get("origin_diagnostic")
    if not isinstance(origin, dict) or origin.get("block_threshold") != 0.9:
        raise ValueError("origin diagnostic block threshold changed")
    if (
        origin.get("requires_deduplication") is not True
        or origin.get("requires_train_fit_only") is not True
    ):
        raise ValueError("origin diagnostic leakage controls are incomplete")

    site = protocol.get("site_calibration")
    if not isinstance(site, dict):
        raise ValueError("site calibration protocol is missing")
    if site.get("approved_benign_only") is not True or site.get("attack_rows_allowed") is not False:
        raise ValueError("site calibration may only use approved benign rows")
    if site.get("human_approval_required") is not True or site.get("rollback_required") is not True:
        raise ValueError("site calibration governance controls are incomplete")

    sequence = protocol.get("sequence")
    if not isinstance(sequence, dict) or sequence.get("max_first_packets") != 20:
        raise ValueError("sequence capacity changed")
    if (
        sequence.get("payloads_read") is not False
        or sequence.get("endpoint_identity_in_features") is not False
    ):
        raise ValueError("sequence privacy boundary is invalid")

    objectives = protocol.get("objectives")
    expected_objectives = {
        "benign_fpr_max": 0.01,
        "preferred_benign_fpr_max": 0.005,
        "unseen_family_direct_recall_min": 0.5,
        "unknown_detection_or_review_min": 0.8,
        "known_recall_min": 0.9,
        "ece_max": 0.1,
        "catastrophic_environment_fpr_max": 0.05,
        "single_flow_latency_ms_max": 10.0,
        "batch_throughput_flows_per_second_min": 500.0,
    }
    if objectives != expected_objectives:
        raise ValueError("predeclared research-v2 objectives changed")
    return development_set, prepared_set, experiment_set


def _validate_pool(
    pool_path: Path,
    prepared_scenarios: set[str],
    reserved_scenario: str,
    frozen_hashes: set[str],
) -> None:
    pool = _read_object(pool_path)
    if set(pool) != prepared_scenarios:
        raise ValueError("research-v2 pool does not match the predeclared prepared scenarios")
    for scenario, entry in pool.items():
        if scenario == reserved_scenario or not isinstance(entry, dict):
            raise ValueError(f"invalid or reserved research-v2 pool scenario: {scenario}")
        pcap_hash = _require_sha(entry.get("pcap_sha256"), f"{scenario}.pcap_sha256")
        labels_hash = _require_sha(entry.get("labels_sha256"), f"{scenario}.labels_sha256")
        if pcap_hash in frozen_hashes or labels_hash in frozen_hashes:
            raise ValueError(f"research-v2 pool overlaps frozen-final source evidence: {scenario}")
        size = entry.get("pcap_size_bytes")
        if not isinstance(size, int) or size <= 0:
            raise ValueError(f"invalid PCAP size for research-v2 scenario: {scenario}")


def _validate_npz(path: Path, prepared_scenarios: set[str]) -> None:
    try:
        archive = np.load(path, allow_pickle=False)
        with archive:
            keys = set(archive.files)
            if keys != _NPZ_KEYS:
                raise ValueError(f"embedding artifact has unexpected fields: {path.name}")
            embeddings = archive["embeddings"]
            labels = archive["binary_label"]
            scenarios = archive["scenario"]
            families = archive["family"]
            if embeddings.ndim != 2 or embeddings.dtype.kind not in {"f", "i", "u"}:
                raise ValueError(f"embedding artifact matrix is invalid: {path.name}")
            if not np.isfinite(embeddings).all():
                raise ValueError(f"embedding artifact contains non-finite values: {path.name}")
            rows = embeddings.shape[0]
            if rows == 0 or embeddings.shape[1] not in {32, 48}:
                raise ValueError(f"embedding artifact dimensions are invalid: {path.name}")
            if any(
                array.ndim != 1 or array.shape[0] != rows
                for array in (labels, scenarios, families)
            ):
                raise ValueError(f"embedding artifact row counts disagree: {path.name}")
            if labels.dtype.kind not in {"f", "i", "u", "b"}:
                raise ValueError(f"embedding labels have an invalid dtype: {path.name}")
            if not np.isfinite(labels.astype(np.float64, copy=False)).all():
                raise ValueError(f"embedding labels contain non-finite values: {path.name}")
            if not np.isin(labels, [0, 1]).all():
                raise ValueError(f"embedding artifact labels must be binary: {path.name}")
            if scenarios.dtype.kind != "U" or families.dtype.kind != "U":
                raise ValueError(f"embedding artifact metadata must be Unicode: {path.name}")
            if not set(scenarios.tolist()) <= prepared_scenarios:
                raise ValueError(f"embedding artifact contains undeclared scenarios: {path.name}")
            if not set(families.tolist()) <= _ARCHIVE_FAMILIES:
                raise ValueError(f"embedding artifact contains undeclared families: {path.name}")
            if not np.array_equal(labels == 0, families == "benign"):
                raise ValueError(f"embedding artifact family/label mismatch: {path.name}")
    except (OSError, ValueError, TypeError) as error:
        if isinstance(error, ValueError) and str(error).startswith("embedding artifact"):
            raise
        raise ValueError(f"invalid embedding artifact: {path.name}") from error


def verify_research_v2(
    root: Path,
    manifest_path: Path | None = None,
) -> ResearchV2Summary:
    """Verify historical archive integrity without asserting research eligibility."""

    root = root.resolve()
    if manifest_path is None:
        manifest_path = root / "configs" / "research-v2" / "evidence-manifest.json"
    elif not manifest_path.is_absolute():
        manifest_path = root / manifest_path
    manifest_path = manifest_path.resolve()
    manifest = _read_object(manifest_path)
    if manifest.get("schema_version") != "1.0.0":
        raise ValueError("research-v2 evidence manifest schema is unsupported")
    if manifest.get("permitted_use") != "development_only":
        raise ValueError("research-v2 evidence must be development-only")
    publication_commit = manifest.get("publication_commit")
    if not isinstance(publication_commit, str) or not _COMMIT.fullmatch(publication_commit):
        raise ValueError("research-v2 publication commit is invalid")
    if (
        manifest.get("scientific_status") != "historical_unvalidated"
        or manifest.get("run_provenance") != "incomplete"
        or "evidence_commit" in manifest
    ):
        raise ValueError("research-v2 archive must disclose incomplete scientific provenance")
    if manifest.get("text_hash_format") != "sha256-utf8-lf":
        raise ValueError("research-v2 text hash format is unsupported")

    protocol_entry = manifest.get("protocol")
    pool_entry = manifest.get("pool_manifest")
    if not isinstance(protocol_entry, dict) or not isinstance(pool_entry, dict):
        raise ValueError("research-v2 protocol or pool binding is missing")
    if (
        protocol_entry.get("path") != "configs/research-v2/protocol.json"
        or pool_entry.get("path") != "configs/research-v2/pool-hashes.json"
    ):
        raise ValueError("research-v2 protocol or pool path changed")
    protocol_path = _require_relative_hash(
        root, protocol_entry.get("path"), protocol_entry.get("sha256"), "protocol"
    )
    pool_path = _require_relative_hash(
        root, pool_entry.get("path"), pool_entry.get("sha256"), "pool manifest"
    )
    protocol = _read_object(protocol_path)
    _, prepared_scenarios, experiment_ids = _validate_protocol(protocol)
    if (
        manifest.get("frozen_manifest") != _FROZEN_MANIFEST
        or protocol.get("frozen_manifest") != _FROZEN_MANIFEST
    ):
        raise ValueError("research-v2 frozen-manifest binding changed")
    if manifest.get("reserved_final_environment") != "CTU-13 scenario 8":
        raise ValueError("research-v2 reserved final environment binding changed")

    frozen_manifest = _safe_path(root, str(manifest.get("frozen_manifest")))
    if not frozen_manifest.is_file():
        raise ValueError("v1 frozen-evidence manifest is missing")
    frozen = _read_object(frozen_manifest)
    policy = frozen.get("policy")
    if (
        not isinstance(policy, dict)
        or policy.get("permitted_use") != "final_acceptance_only"
        or policy.get("development_use_allowed") is not False
    ):
        raise ValueError("v1 frozen evidence policy is not final-only")
    frozen_hashes = frozen_source_hashes(frozen_manifest)
    _validate_pool(pool_path, prepared_scenarios, "CTU-13 scenario 8", frozen_hashes)

    entries = manifest.get("experiments")
    if not isinstance(entries, list) or len(entries) != len(experiment_ids):
        raise ValueError("research-v2 experiment manifest is incomplete")
    seen_ids: set[str] = set()
    bound_paths: set[str] = {protocol_entry["path"], pool_entry["path"]}
    report_paths: set[str] = set()
    artifact_paths: set[str] = set()
    artifact_count = 0
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("research-v2 experiment entry is invalid")
        experiment_id = entry.get("experiment_id")
        if not isinstance(experiment_id, str) or experiment_id not in experiment_ids:
            raise ValueError("research-v2 experiment ID is not predeclared")
        if experiment_id in seen_ids:
            raise ValueError(f"duplicate research-v2 experiment: {experiment_id}")
        seen_ids.add(experiment_id)
        report_path_value = entry.get("report_path")
        report_path = _require_relative_hash(
            root,
            report_path_value,
            entry.get("report_sha256"),
            f"{experiment_id} report",
        )
        if (
            report_path.suffix != ".json"
            or report_path.parent != (root / _ARCHIVE_NAMESPACE).resolve()
        ):
            raise ValueError(
                f"research-v2 report is outside the experiment namespace: {experiment_id}"
            )
        report_path_key = cast(str, report_path_value).replace("\\", "/")
        if report_path_key in report_paths:
            raise ValueError(f"duplicate research-v2 report path: {report_path_key}")
        report_paths.add(report_path_key)
        bound_paths.add(report_path_key)
        report = _read_object(report_path)
        if report.get("experiment_id") != experiment_id:
            raise ValueError(f"research-v2 report ID mismatch: {experiment_id}")
        if report.get("schema_version") != _EXPERIMENT_SCHEMA:
            raise ValueError(f"research-v2 report schema mismatch: {experiment_id}")
        if report.get("seed") != protocol.get("seed"):
            raise ValueError(f"research-v2 report seed mismatch: {experiment_id}")
        if report.get("status") not in _PERMITTED_STATUS:
            raise ValueError(f"research-v2 report is not development-only: {experiment_id}")
        _reject_sensitive_keys(report, experiment_id)
        report_strings = _strings(report)
        if any(
            "docs/evaluation" in value or "configs/evaluation" in value
            for value in report_strings
        ):
            raise ValueError(f"research-v2 report references frozen-final paths: {experiment_id}")
        if any(value in frozen_hashes for value in report_strings):
            raise ValueError(
                f"research-v2 report embeds a frozen-final source hash: {experiment_id}"
            )
        if any("CTU-13 scenario 8" in value for value in report_strings):
            raise ValueError(f"reserved final environment leaked into v2 evidence: {experiment_id}")

        artifacts = entry.get("artifacts")
        if not isinstance(artifacts, list):
            raise ValueError(f"research-v2 artifact list is invalid: {experiment_id}")
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                raise ValueError(f"research-v2 artifact entry is invalid: {experiment_id}")
            artifact_path_value = artifact.get("path")
            artifact_path = _require_relative_hash(
                root,
                artifact_path_value,
                artifact.get("sha256"),
                f"{experiment_id} artifact",
            )
            if (
                artifact_path.suffix != ".npz"
                or artifact_path.parent != (root / _ARCHIVE_NAMESPACE).resolve()
            ):
                raise ValueError(
                    f"research-v2 artifact is outside the archive namespace: {artifact_path.name}"
                )
            artifact_key = cast(str, artifact_path_value).replace("\\", "/")
            if artifact_key in artifact_paths or artifact_key in bound_paths:
                raise ValueError(f"duplicate research-v2 artifact path: {artifact_key}")
            artifact_paths.add(artifact_key)
            bound_paths.add(artifact_key)
            _validate_npz(artifact_path, prepared_scenarios)
            artifact_count += 1

    if seen_ids != experiment_ids:
        raise ValueError("research-v2 experiment set does not match the protocol")
    namespace = root / "docs" / "research-v2" / "experiments"
    actual_files = {
        path.relative_to(root).as_posix() for path in namespace.rglob("*") if path.is_file()
    }
    if actual_files != report_paths | artifact_paths:
        raise ValueError("unbound files exist in the research-v2 experiment namespace")

    return ResearchV2Summary(
        experiments_verified=len(seen_ids),
        artifacts_verified=artifact_count,
        prepared_scenarios_verified=len(prepared_scenarios),
        publication_commit=publication_commit,
    )


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Verify Detector-v2 development evidence")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--manifest", type=Path, default=None)
    args = parser.parse_args()
    try:
        summary = verify_research_v2(args.root, args.manifest)
    except ValueError as error:
        raise SystemExit(f"research-v2 verification failed: {error}") from error
    print(
        f"verified {summary.experiments_verified} research-v2 experiments, "
        f"{summary.artifacts_verified} embedding artifacts, and "
        f"{summary.prepared_scenarios_verified} prepared scenarios; "
        f"publication_commit={summary.publication_commit}; "
        f"scientific_status={summary.scientific_status} (integrity only)"
    )


if __name__ == "__main__":
    main()
