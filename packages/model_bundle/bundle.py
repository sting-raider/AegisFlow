from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib

from packages.features.registry import FEATURE_NAMES

REQUIRED_FILES = {
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


class BundleError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class ModelBundle:
    root: Path
    manifest: dict[str, Any]
    thresholds: dict[str, Any]
    labels: dict[str, str]
    preprocessor: Any
    classifier: Any
    anomaly: Any

    @property
    def version(self) -> str:
        return str(self.manifest["version"])

    @classmethod
    def load(cls, root: Path) -> ModelBundle:
        missing = (
            REQUIRED_FILES - {path.name for path in root.iterdir()}
            if root.exists()
            else REQUIRED_FILES
        )
        if missing:
            raise BundleError(f"model bundle missing files: {', '.join(sorted(missing))}")
        expected: dict[str, str] = {}
        for line in (root / "checksums.sha256").read_text(encoding="utf-8").splitlines():
            digest, filename = line.split(maxsplit=1)
            expected[filename.strip()] = digest
        for filename, digest in expected.items():
            target = root / filename
            if not target.is_file() or sha256_file(target) != digest:
                raise BundleError(f"checksum mismatch: {filename}")

        manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        schema = json.loads((root / "feature_schema.json").read_text(encoding="utf-8"))
        if manifest.get("feature_schema_version") != "1.0.0":
            raise BundleError("unsupported feature schema version")
        if tuple(schema.get("feature_order", [])) != FEATURE_NAMES:
            raise BundleError("feature order is incompatible with detector")
        if manifest.get("artifact_format") != "joblib-local-trusted":
            raise BundleError("unsupported artifact format")

        # joblib is intentionally loaded only after every artifact hash and schema
        # are validated. Registry write access must be trusted.
        return cls(
            root=root,
            manifest=manifest,
            thresholds=json.loads((root / "thresholds.json").read_text(encoding="utf-8")),
            labels=json.loads((root / "label_mapping.json").read_text(encoding="utf-8")),
            preprocessor=joblib.load(root / "preprocessor.joblib"),
            classifier=joblib.load(root / "classifier.joblib"),
            anomaly=joblib.load(root / "anomaly.joblib"),
        )


def load_production_bundle(
    registry: Path = Path("models/registry"),
    model_name: str = "aegisflow-smoke",
) -> ModelBundle:
    pointer = registry / model_name / "production.json"
    if not pointer.is_file():
        raise BundleError(f"production pointer not found: {pointer}")
    data = json.loads(pointer.read_text(encoding="utf-8"))
    version = data.get("version")
    if not isinstance(version, str) or not version:
        raise BundleError("invalid production pointer")
    return ModelBundle.load(registry / model_name / version)
