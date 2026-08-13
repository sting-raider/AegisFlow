from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from alembic.config import Config
from alembic.script import ScriptDirectory


class ReleaseManifestError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_checksum_manifest(bundle: Path) -> dict[str, str]:
    checksum_file = bundle / "checksums.sha256"
    if not checksum_file.is_file():
        raise ReleaseManifestError("model checksum manifest is missing")
    hashes: dict[str, str] = {}
    for line in checksum_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            raise ReleaseManifestError("model checksum manifest has an invalid line")
        expected, relative = parts[0], parts[1].lstrip("* ")
        if len(expected) != 64 or any(char not in "0123456789abcdef" for char in expected):
            raise ReleaseManifestError("model checksum manifest has an invalid digest")
        target = (bundle / relative).resolve()
        if bundle.resolve() not in target.parents or not target.is_file():
            raise ReleaseManifestError("model checksum target escapes or is missing")
        if sha256_file(target) != expected:
            raise ReleaseManifestError(f"model artifact checksum mismatch: {relative}")
        hashes[relative] = expected
    if not hashes:
        raise ReleaseManifestError("model checksum manifest is empty")
    return hashes


def validate_sbom(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.stat().st_size > 50_000_000:
        raise ReleaseManifestError(f"SBOM is missing or oversized: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseManifestError(f"SBOM is not valid JSON: {path}") from exc
    if not isinstance(payload, dict) or payload.get("bomFormat") != "CycloneDX":
        raise ReleaseManifestError(f"SBOM is not CycloneDX: {path}")
    components = payload.get("components")
    if not isinstance(components, list) or not components:
        raise ReleaseManifestError(f"SBOM has no components: {path}")
    return {
        "format": "CycloneDX",
        "spec_version": payload.get("specVersion"),
        "component_count": len(components),
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def _run(arguments: list[str]) -> str:
    result = subprocess.run(arguments, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        raise ReleaseManifestError(f"release command returned nonzero: {' '.join(arguments)}")
    return result.stdout.strip()


def _image(image: str) -> dict[str, Any]:
    raw = _run(["docker", "image", "inspect", image])
    payload = json.loads(raw)
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        raise ReleaseManifestError(f"image inspection was invalid: {image}")
    item = cast(dict[str, Any], payload[0])
    image_id = item.get("Id")
    if not isinstance(image_id, str) or not image_id.startswith("sha256:"):
        raise ReleaseManifestError(f"image has no immutable content ID: {image}")
    return {
        "build_reference": image,
        "content_id": image_id,
        "size_bytes": int(item.get("Size", 0)),
        "registry_digest_required_for_production": True,
    }


def build_manifest(
    *,
    backend_image: str,
    dashboard_image: str,
    backend_sbom: Path,
    dashboard_sbom: Path,
) -> dict[str, Any]:
    if _run(["git", "status", "--porcelain"]):
        raise ReleaseManifestError("release workspace has tracked or untracked changes")
    commit = _run(["git", "rev-parse", "HEAD"])
    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))["project"]
    pointer_path = Path("models/registry/aegisflow-smoke/production.json")
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    version = str(pointer["version"])
    bundle = pointer_path.parent / version
    bundle_manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    feature_schema = json.loads((bundle / "feature_schema.json").read_text(encoding="utf-8"))
    model_hashes = verify_checksum_manifest(bundle)
    migration = ScriptDirectory.from_config(Config("alembic.ini")).get_current_head()
    if migration is None:
        raise ReleaseManifestError("Alembic has no migration head")
    rule_paths = sorted(Path("configs/suricata/rules").glob("*.rules"))
    if not rule_paths:
        raise ReleaseManifestError("Suricata rules are missing")
    return {
        "schema_version": "1.0.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "release": {
            "application": str(project["name"]),
            "application_version": str(project["version"]),
            "git_commit": commit,
            "workspace_clean": True,
            "production_eligibility": "no-go",
            "production_eligibility_reason": (
                "no model candidate passed development selection; frozen final evidence "
                "remains sealed"
            ),
        },
        "containers": {
            "backend": {**_image(backend_image), "sbom": validate_sbom(backend_sbom)},
            "dashboard": {
                **_image(dashboard_image),
                "sbom": validate_sbom(dashboard_sbom),
            },
        },
        "database": {"migration_head": migration},
        "model": {
            "name": bundle_manifest["model_name"],
            "version": bundle_manifest["version"],
            "bundle_schema_version": bundle_manifest["bundle_schema_version"],
            "pointer_sha256": sha256_file(pointer_path),
            "checksum_manifest_sha256": sha256_file(bundle / "checksums.sha256"),
            "verified_artifact_count": len(model_hashes),
            "scientific_status": "synthetic-smoke-only-rejected-for-production",
        },
        "feature_schema": {
            "version": feature_schema["schema_version"],
            "sha256": sha256_file(bundle / "feature_schema.json"),
            "feature_count": len(feature_schema["feature_order"]),
        },
        "suricata": {
            "image": "jasonish/suricata:8.0.6",
            "rules": [
                {"path": path.as_posix(), "sha256": sha256_file(path)} for path in rule_paths
            ],
        },
        "configuration": {
            "contract_version": "1.0.0",
            "production_validator_sha256": sha256_file(Path("scripts/production_check.py")),
        },
        "dependency_locks": {
            "python": {"path": "uv.lock", "sha256": sha256_file(Path("uv.lock"))},
            "dashboard": {
                "path": "apps/dashboard/package-lock.json",
                "sha256": sha256_file(Path("apps/dashboard/package-lock.json")),
            },
        },
        "provenance": {
            "builder": "GitHub Actions" if os.getenv("GITHUB_ACTIONS") == "true" else "local",
            "workflow_run_id": os.getenv("GITHUB_RUN_ID"),
            "workflow_sha": os.getenv("GITHUB_SHA"),
            "runner_os": os.getenv("RUNNER_OS", platform.system()),
            "python": platform.python_version(),
            "sbom_generator": "syft-1.51.0",
        },
        "limitations": [
            "Local Docker content IDs are immutable build evidence but registry digests "
            "are required for deployment.",
            "This manifest records a scientifically rejected development snapshot, not a "
            "production release.",
            "Signing and transparency-log publication require the release owner's external "
            "identity and registry.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build an aggregate AegisFlow release manifest")
    parser.add_argument("--backend-image", required=True)
    parser.add_argument("--dashboard-image", required=True)
    parser.add_argument("--backend-sbom", required=True, type=Path)
    parser.add_argument("--dashboard-sbom", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    manifest = build_manifest(
        backend_image=args.backend_image,
        dashboard_image=args.dashboard_image,
        backend_sbom=args.backend_sbom,
        dashboard_sbom=args.dashboard_sbom,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "git_commit": manifest["release"]["git_commit"]}))


if __name__ == "__main__":
    main()
