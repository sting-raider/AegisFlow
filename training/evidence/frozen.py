from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

CONFIG_PROJECTION_VERSION = "1.0.0"
EXPECTED_PERMITTED_USE = "final_acceptance_only"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


class FrozenEvidenceError(ValueError):
    """Raised when immutable final evidence or its policy manifest is invalid."""


@dataclass(frozen=True)
class FrozenEvidenceSummary:
    manifest: str
    reports_verified: int
    source_fingerprints_verified: int
    permitted_use: str


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _gate_configuration(gate: object) -> dict[str, object]:
    if not isinstance(gate, dict):
        raise FrozenEvidenceError("report readiness_gate must be an object")
    criteria = gate.get("criteria")
    if not isinstance(criteria, dict):
        raise FrozenEvidenceError("report readiness_gate.criteria must be an object")
    projected: dict[str, dict[str, object]] = {}
    for name, criterion in criteria.items():
        if not isinstance(name, str) or not isinstance(criterion, dict):
            raise FrozenEvidenceError("report readiness criteria must be named objects")
        projected[name] = {
            "operator": criterion.get("operator"),
            "threshold": criterion.get("threshold"),
        }
    return {"criteria": projected, "policy": gate.get("policy")}


def evaluation_config_projection(report: dict[str, Any]) -> dict[str, object]:
    """Return only inputs and policy—not outcomes—from a frozen evaluation report."""

    evaluation = report.get("evaluation")
    if not isinstance(evaluation, dict):
        raise FrozenEvidenceError("report evaluation must be an object")
    return {
        "projection_version": CONFIG_PROJECTION_VERSION,
        "report_schema_version": report.get("schema_version"),
        "dataset": report.get("dataset"),
        "dataset_fingerprint": report.get("fingerprint"),
        "evaluation_mode": report.get("evaluation_mode"),
        "split": report.get("split"),
        "evaluation_bundle": report.get("evaluation_bundle"),
        "feature_order": evaluation.get("feature_order"),
        "fit_manifest": evaluation.get("fit_manifest"),
        "harness": evaluation.get("harness"),
        "seed": evaluation.get("seed"),
        "shared_inference_path": evaluation.get("shared_inference_path"),
        "train_rows": evaluation.get("train_rows"),
        "test_rows": evaluation.get("test_rows"),
        "training_dataset": evaluation.get("training_dataset"),
        "training_fingerprint": evaluation.get("training_fingerprint"),
        "testing_dataset": evaluation.get("testing_dataset"),
        "testing_fingerprint": evaluation.get("testing_fingerprint"),
        "training_classes": evaluation.get("training_classes"),
        "unknown_test_families": evaluation.get("unknown_test_families"),
        "readiness_gate": _gate_configuration(evaluation.get("readiness_gate")),
    }


def evaluation_config_sha256(report: dict[str, Any]) -> str:
    return canonical_json_sha256(evaluation_config_projection(report))


def _object_list(value: object, *, field: str) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list) and all(isinstance(item, dict) for item in value):
        return value
    raise FrozenEvidenceError(f"{field} must be an object or an array of objects")


def source_fingerprints(report: dict[str, Any]) -> list[dict[str, str | int]]:
    sources: list[dict[str, str | int]] = []
    for field in ("provenance", "cross_provenance"):
        value = report.get(field)
        if value is None:
            continue
        for item in _object_list(value, field=field):
            filename = item.get("filename")
            size_bytes = item.get("size_bytes")
            digest = item.get("sha256")
            if not isinstance(filename, str) or not filename:
                raise FrozenEvidenceError(f"{field} filename must be a nonempty string")
            if not isinstance(size_bytes, int) or size_bytes <= 0:
                raise FrozenEvidenceError(f"{field} size_bytes must be a positive integer")
            if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
                raise FrozenEvidenceError(f"{field} sha256 must be lowercase SHA-256")
            sources.append(
                {"filename": filename, "size_bytes": size_bytes, "sha256": digest}
            )
    if not sources:
        raise FrozenEvidenceError("report has no source provenance fingerprints")
    return sorted(sources, key=lambda item: (str(item["filename"]), str(item["sha256"])))


def _resolve_repository_path(repository_root: Path, relative: object, *, field: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise FrozenEvidenceError(f"{field} must be a nonempty repository-relative path")
    root = repository_root.resolve()
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise FrozenEvidenceError(f"{field} escapes repository root: {relative}") from error
    return candidate


def _load_object(path: Path, *, label: str) -> dict[str, Any]:
    try:
        decoded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FrozenEvidenceError(f"cannot read {label} {path}: {error}") from error
    if not isinstance(decoded, dict):
        raise FrozenEvidenceError(f"{label} must be a JSON object: {path}")
    return decoded


def verify_frozen_evidence(
    manifest_path: Path,
    *,
    repository_root: Path,
) -> FrozenEvidenceSummary:
    manifest = _load_object(manifest_path, label="frozen-evidence manifest")
    if manifest.get("schema_version") != "1.0.0":
        raise FrozenEvidenceError("unsupported frozen-evidence manifest schema_version")
    policy = manifest.get("policy")
    if not isinstance(policy, dict):
        raise FrozenEvidenceError("manifest policy must be an object")
    required_policy = {
        "permitted_use": EXPECTED_PERMITTED_USE,
        "development_use_allowed": False,
        "candidate_lock_required_before_final_run": True,
        "maximum_final_runs_per_locked_candidate": 1,
    }
    for key, expected in required_policy.items():
        if policy.get(key) != expected:
            raise FrozenEvidenceError(f"manifest policy {key} must equal {expected!r}")

    reports = manifest.get("reports")
    if not isinstance(reports, list) or not reports:
        raise FrozenEvidenceError("manifest reports must be a nonempty array")
    seen_ids: set[str] = set()
    source_count = 0
    for entry in reports:
        if not isinstance(entry, dict):
            raise FrozenEvidenceError("each frozen report entry must be an object")
        report_id = entry.get("id")
        if not isinstance(report_id, str) or not report_id or report_id in seen_ids:
            raise FrozenEvidenceError("frozen report ids must be unique nonempty strings")
        seen_ids.add(report_id)
        if entry.get("permitted_use") != EXPECTED_PERMITTED_USE:
            raise FrozenEvidenceError(f"{report_id}: permitted_use must be final_acceptance_only")
        commit = entry.get("published_commit")
        if not isinstance(commit, str) or not _COMMIT.fullmatch(commit):
            raise FrozenEvidenceError(f"{report_id}: published_commit must be a full commit SHA")
        published_at = entry.get("published_at")
        if not isinstance(published_at, str) or "T" not in published_at:
            raise FrozenEvidenceError(f"{report_id}: published_at must be an ISO-8601 timestamp")

        report_path = _resolve_repository_path(
            repository_root, entry.get("path"), field=f"{report_id}.path"
        )
        if not report_path.is_file():
            raise FrozenEvidenceError(f"{report_id}: frozen report is missing: {report_path}")
        expected_report_sha = entry.get("report_sha256")
        if not isinstance(expected_report_sha, str) or not _SHA256.fullmatch(expected_report_sha):
            raise FrozenEvidenceError(f"{report_id}: report_sha256 must be lowercase SHA-256")
        actual_report_sha = sha256_file(report_path)
        if actual_report_sha != expected_report_sha:
            raise FrozenEvidenceError(
                f"{report_id}: report hash mismatch ({actual_report_sha} != {expected_report_sha})"
            )

        report = _load_object(report_path, label="frozen report")
        expected_config_sha = entry.get("evaluation_config_sha256")
        if not isinstance(expected_config_sha, str) or not _SHA256.fullmatch(expected_config_sha):
            raise FrozenEvidenceError(
                f"{report_id}: evaluation_config_sha256 must be lowercase SHA-256"
            )
        actual_config_sha = evaluation_config_sha256(report)
        if actual_config_sha != expected_config_sha:
            raise FrozenEvidenceError(
                f"{report_id}: evaluation config hash mismatch "
                f"({actual_config_sha} != {expected_config_sha})"
            )

        evaluation = report.get("evaluation")
        assert isinstance(evaluation, dict)
        readiness_gate = evaluation.get("readiness_gate")
        if not isinstance(readiness_gate, dict):
            raise FrozenEvidenceError(f"{report_id}: readiness gate is missing")
        if readiness_gate.get("status") != "fail":
            raise FrozenEvidenceError(f"{report_id}: legacy frozen evidence must remain rejected")
        if readiness_gate.get("automatic_promotion_allowed") is not False:
            raise FrozenEvidenceError(f"{report_id}: automatic promotion must remain disabled")

        expected_sources = entry.get("source_files")
        if not isinstance(expected_sources, list):
            raise FrozenEvidenceError(f"{report_id}: source_files must be an array")
        normalized_expected = sorted(
            expected_sources,
            key=lambda item: (
                str(item.get("filename")) if isinstance(item, dict) else "",
                str(item.get("sha256")) if isinstance(item, dict) else "",
            ),
        )
        actual_sources = source_fingerprints(report)
        if normalized_expected != actual_sources:
            raise FrozenEvidenceError(f"{report_id}: source fingerprint manifest mismatch")
        source_count += len(actual_sources)

    return FrozenEvidenceSummary(
        manifest=str(manifest_path.resolve()),
        reports_verified=len(reports),
        source_fingerprints_verified=source_count,
        permitted_use=EXPECTED_PERMITTED_USE,
    )
