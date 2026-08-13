import hashlib
import json
from pathlib import Path

import pytest

from scripts.build_release_manifest import (
    ReleaseManifestError,
    validate_sbom,
    verify_checksum_manifest,
)


def test_verify_checksum_manifest_accepts_bound_artifact(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"safe fixture")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    (tmp_path / "checksums.sha256").write_text(f"{digest}  artifact.bin\n", encoding="utf-8")
    assert verify_checksum_manifest(tmp_path) == {"artifact.bin": digest}


def test_verify_checksum_manifest_rejects_traversal(tmp_path: Path) -> None:
    (tmp_path / "checksums.sha256").write_text(f"{'0' * 64}  ../escape\n", encoding="utf-8")
    with pytest.raises(ReleaseManifestError, match="escapes or is missing"):
        verify_checksum_manifest(tmp_path)


def test_validate_sbom_requires_nonempty_cyclonedx(tmp_path: Path) -> None:
    sbom = tmp_path / "sbom.json"
    sbom.write_text(
        json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{}]}),
        encoding="utf-8",
    )
    result = validate_sbom(sbom)
    assert result["format"] == "CycloneDX"
    assert result["component_count"] == 1
