from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from training.data.development import frozen_source_hashes

_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PROHIBITED_KEYS = {
    "destination_ip",
    "dst_ip",
    "predictions",
    "source_ip",
    "src_ip",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_path(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise ValueError(f"research artifact escapes repository: {relative}") from error
    if relative.replace("\\", "/").startswith("data/"):
        raise ValueError("research artifacts cannot reference raw data paths")
    return candidate


def _reject_sensitive_keys(value: Any) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if str(key).lower() in _PROHIBITED_KEYS:
                raise ValueError(f"research report contains prohibited key: {key}")
            _reject_sensitive_keys(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_sensitive_keys(nested)


def verify_research_experiments(root: Path) -> tuple[int, int]:
    root = root.resolve()
    registry_dir = root / "configs" / "research" / "experiments"
    registries = sorted(registry_dir.glob("*.json"))
    if not registries:
        raise ValueError("no registered research experiments found")
    frozen = frozen_source_hashes(
        root / "configs" / "evaluation" / "frozen-evidence-v1.json"
    )
    artifact_count = 0
    for registry_path in registries:
        registry = json.loads(registry_path.read_text(encoding="utf-8"))
        if not isinstance(registry, dict):
            raise ValueError(f"experiment registry must be an object: {registry_path.name}")
        experiment_id = registry.get("experiment_id")
        if not isinstance(experiment_id, str) or experiment_id != registry_path.stem:
            raise ValueError(f"experiment ID does not match filename: {registry_path.name}")
        if registry.get("permitted_use") != "development_only":
            raise ValueError(f"experiment must be development-only: {experiment_id}")
        commit = registry.get("code_commit")
        if not isinstance(commit, str) or not _COMMIT.fullmatch(commit):
            raise ValueError(f"experiment code commit is invalid: {experiment_id}")
        artifacts = registry.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            raise ValueError(f"experiment artifacts are missing: {experiment_id}")
        decoded_reports: list[dict[str, Any]] = []
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                raise ValueError(f"experiment artifact is invalid: {experiment_id}")
            relative = artifact.get("path")
            expected = artifact.get("sha256")
            if not isinstance(relative, str) or not isinstance(expected, str):
                raise ValueError(f"experiment artifact fields are invalid: {experiment_id}")
            if not _SHA256.fullmatch(expected):
                raise ValueError(f"experiment artifact hash is invalid: {relative}")
            path = _safe_path(root, relative)
            if not path.is_file() or _sha256(path) != expected:
                raise ValueError(f"experiment artifact hash mismatch: {relative}")
            artifact_count += 1
            if path.suffix == ".json" and path != registry_path:
                decoded = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(decoded, dict) and decoded.get("experiment_id") == experiment_id:
                    decoded_reports.append(decoded)
        if len(decoded_reports) != 1:
            raise ValueError(
                f"experiment requires exactly one primary JSON report: {experiment_id}"
            )
        report = decoded_reports[0]
        _reject_sensitive_keys(report)
        if report.get("code_commit") != commit:
            raise ValueError(f"experiment report commit mismatch: {experiment_id}")
        if report.get("feature_order") != registry.get("feature_order"):
            raise ValueError(f"experiment feature order mismatch: {experiment_id}")
        if report.get("seed") != registry.get("seed"):
            raise ValueError(f"experiment seed mismatch: {experiment_id}")
        report_fingerprints = {
            str(item.get("source_id")): str(item.get("dataset_fingerprint"))
            for item in report.get("sources", [])
            if isinstance(item, dict)
        }
        if report_fingerprints != registry.get("dataset_fingerprints"):
            raise ValueError(f"experiment dataset fingerprints mismatch: {experiment_id}")
        source_hashes = {
            str(value)
            for item in report.get("sources", [])
            if isinstance(item, dict)
            for value in item.get("provenance_sha256", [])
        }
        if source_hashes & frozen:
            raise ValueError(f"experiment uses frozen-final source evidence: {experiment_id}")
    return len(registries), artifact_count


def main() -> None:
    experiments, artifacts = verify_research_experiments(Path.cwd())
    print(f"verified {experiments} research experiments and {artifacts} artifacts")


if __name__ == "__main__":
    main()
