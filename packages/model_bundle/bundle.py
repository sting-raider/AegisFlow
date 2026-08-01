from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import uuid4

import joblib
import torch

from packages.features.registry import FEATURE_NAMES

if TYPE_CHECKING:
    from packages.detection.autoencoder import DenoisingAutoencoder

BASE_REQUIRED_FILES = {
    "manifest.json",
    "feature_schema.json",
    "preprocessor.joblib",
    "classifier.joblib",
    "anomaly.joblib",
    "label_mapping.json",
    "thresholds.json",
    "metrics.json",
    "training_config.yaml",
    "training_data_manifest.json",
    "checksums.sha256",
}
V2_REQUIRED_FILES = BASE_REQUIRED_FILES | {"autoencoder.pt"}
MAX_POINTER_HISTORY = 5


class BundleError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: Path, description: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BundleError(f"invalid {description}: {path}") from exc
    if not isinstance(value, dict):
        raise BundleError(f"invalid {description}: expected an object")
    return value


def _read_checksums(root: Path) -> dict[str, str]:
    expected: dict[str, str] = {}
    try:
        lines = (root / "checksums.sha256").read_text(encoding="utf-8").splitlines()
        for line in lines:
            digest, filename = line.split(maxsplit=1)
            filename = filename.strip()
            if len(digest) != 64 or not filename or Path(filename).name != filename:
                raise ValueError
            expected[filename] = digest
    except (OSError, UnicodeError, ValueError) as exc:
        raise BundleError("invalid checksums file") from exc
    return expected


@dataclass(frozen=True)
class ModelBundle:
    root: Path
    manifest: dict[str, Any]
    thresholds: dict[str, Any]
    labels: dict[str, str]
    preprocessor: Any
    classifier: Any
    anomaly: Any
    autoencoder: DenoisingAutoencoder | None = None
    load_warning: str | None = None

    @property
    def version(self) -> str:
        return str(self.manifest["version"])

    @classmethod
    def load(cls, root: Path) -> ModelBundle:
        if not root.is_dir():
            raise BundleError(f"model bundle not found: {root}")
        manifest = _read_json(root / "manifest.json", "manifest")
        if manifest.get("version") != root.name:
            raise BundleError("bundle directory and manifest versions do not match")
        bundle_schema = int(manifest.get("bundle_schema_version", 1))
        required = V2_REQUIRED_FILES if bundle_schema >= 2 else BASE_REQUIRED_FILES
        missing = required - {path.name for path in root.iterdir()}
        if missing:
            raise BundleError(f"model bundle missing files: {', '.join(sorted(missing))}")

        expected = _read_checksums(root)
        if not required - {"checksums.sha256"} <= expected.keys():
            raise BundleError("checksums file does not cover every required artifact")
        for filename, digest in expected.items():
            target = root / filename
            if not target.is_file() or sha256_file(target) != digest:
                raise BundleError(f"checksum mismatch: {filename}")

        schema = _read_json(root / "feature_schema.json", "feature schema")
        if manifest.get("feature_schema_version") != "1.0.0":
            raise BundleError("unsupported feature schema version")
        if tuple(schema.get("feature_order", [])) != FEATURE_NAMES:
            raise BundleError("feature order is incompatible with detector")
        supported_formats = {"joblib-local-trusted", "joblib-local-trusted+torch-state-dict"}
        if manifest.get("artifact_format") not in supported_formats:
            raise BundleError("unsupported artifact format")

        if bundle_schema >= 2:
            artifact_hashes = manifest.get("artifact_hashes")
            if not isinstance(artifact_hashes, dict):
                raise BundleError("bundle manifest is missing artifact hashes")
            for filename in (
                "preprocessor.joblib",
                "classifier.joblib",
                "anomaly.joblib",
                "autoencoder.pt",
            ):
                artifact_digest = artifact_hashes.get(filename)
                if (
                    not isinstance(artifact_digest, str)
                    or sha256_file(root / filename) != artifact_digest
                ):
                    raise BundleError(f"manifest artifact hash mismatch: {filename}")

        # Serialized objects are loaded only after checksums, schema compatibility,
        # and the v2 manifest's independent artifact hashes are verified. Registry
        # write access is therefore a trusted administrative boundary.
        autoencoder: DenoisingAutoencoder | None = None
        if bundle_schema >= 2:
            try:
                from packages.detection.autoencoder import DenoisingAutoencoder

                artifact = torch.load(
                    root / "autoencoder.pt", map_location="cpu", weights_only=True
                )
                if not isinstance(artifact, dict):
                    raise TypeError("autoencoder artifact is not a mapping")
                autoencoder = DenoisingAutoencoder.from_artifact(artifact)
            except (OSError, RuntimeError, TypeError, KeyError, ValueError) as exc:
                raise BundleError("invalid autoencoder artifact") from exc

        return cls(
            root=root,
            manifest=manifest,
            thresholds=_read_json(root / "thresholds.json", "thresholds"),
            labels={
                str(key): str(value)
                for key, value in _read_json(root / "label_mapping.json", "label mapping").items()
            },
            preprocessor=joblib.load(root / "preprocessor.joblib"),
            classifier=joblib.load(root / "classifier.joblib"),
            anomaly=joblib.load(root / "anomaly.joblib"),
            autoencoder=autoencoder,
        )


def _version_key(value: str) -> tuple[tuple[int, ...], str]:
    try:
        return tuple(int(part) for part in value.split(".")), value
    except ValueError:
        return (), value


def _candidate_versions(model_root: Path, pointer: dict[str, Any] | None) -> list[str]:
    candidates: list[str] = []
    if pointer is not None:
        current = pointer.get("version")
        if isinstance(current, str) and current:
            candidates.append(current)
        history = pointer.get("history", [])
        if isinstance(history, list):
            candidates.extend(item for item in history if isinstance(item, str) and item)
    if model_root.is_dir():
        candidates.extend(
            path.name
            for path in sorted(
                (item for item in model_root.iterdir() if item.is_dir()),
                key=lambda item: _version_key(item.name),
                reverse=True,
            )
        )
    return list(dict.fromkeys(candidates))


def load_production_bundle(
    registry: Path = Path("models/registry"),
    model_name: str = "aegisflow-smoke",
) -> ModelBundle:
    model_root = registry / model_name
    pointer_path = model_root / "production.json"
    pointer: dict[str, Any] | None = None
    pointer_error: str | None = None
    if pointer_path.is_file():
        try:
            pointer = _read_json(pointer_path, "production pointer")
        except BundleError as exc:
            pointer_error = str(exc)
    else:
        pointer_error = f"production pointer not found: {pointer_path}"

    candidates = _candidate_versions(model_root, pointer)
    failures: list[str] = []
    for index, version in enumerate(candidates):
        try:
            bundle = ModelBundle.load(model_root / version)
        except BundleError as exc:
            failures.append(f"{version}: {exc}")
            continue
        if index == 0 and pointer_error is None:
            return bundle
        warning_parts = []
        if pointer_error:
            warning_parts.append(pointer_error)
        warning_parts.extend(failures)
        warning_parts.append(f"loaded previous valid model version {version}")
        return replace(bundle, load_warning="; ".join(warning_parts))

    detail = "; ".join(filter(None, [pointer_error, *failures]))
    raise BundleError(f"no valid production model bundle is available: {detail}")


def promote_bundle(
    registry: Path,
    model_name: str,
    version: str,
    *,
    max_history: int = MAX_POINTER_HISTORY,
) -> Path:
    if not version or Path(version).name != version:
        raise BundleError("invalid model version")
    model_root = registry / model_name
    ModelBundle.load(model_root / version)
    pointer = model_root / "production.json"
    previous: dict[str, Any] = {}
    if pointer.is_file():
        previous = _read_json(pointer, "production pointer")
    history: list[str] = []
    previous_version = previous.get("version")
    if isinstance(previous_version, str) and previous_version != version:
        history.append(previous_version)
    previous_history = previous.get("history", [])
    if isinstance(previous_history, list):
        history.extend(
            item for item in previous_history if isinstance(item, str) and item != version
        )
    history = list(dict.fromkeys(history))[: max(0, max_history)]
    payload = {
        "version": version,
        "updated_at": datetime.now(UTC).isoformat(),
        "history": history,
    }
    model_root.mkdir(parents=True, exist_ok=True)
    temporary = model_root / f".production-{uuid4().hex}.tmp"
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, pointer)
    finally:
        temporary.unlink(missing_ok=True)
    return pointer


def rollback_production_bundle(
    registry: Path,
    model_name: str = "aegisflow-smoke",
) -> ModelBundle:
    pointer = _read_json(registry / model_name / "production.json", "production pointer")
    history = pointer.get("history", [])
    if not isinstance(history, list) or not history or not isinstance(history[0], str):
        raise BundleError("no previous model version is recorded for rollback")
    promote_bundle(registry, model_name, history[0])
    return load_production_bundle(registry, model_name)
