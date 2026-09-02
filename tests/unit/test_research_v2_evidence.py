from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import numpy as np
import pytest

from scripts.verify_research_v2 import _safe_path, verify_research_v2

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def _sha256(path: Path) -> str:
    content = path.read_bytes()
    if path.suffix == ".json":
        content = content.replace(b"\r\n", b"\n")
    return hashlib.sha256(content).hexdigest()


def _copy_fixture(root: Path) -> None:
    shutil.copytree(
        REPOSITORY_ROOT / "configs" / "research-v2",
        root / "configs" / "research-v2",
    )
    shutil.copytree(
        REPOSITORY_ROOT / "docs" / "research-v2" / "experiments",
        root / "docs" / "research-v2" / "experiments",
    )
    frozen = root / "configs" / "evaluation" / "frozen-evidence-v1.json"
    frozen.parent.mkdir(parents=True)
    frozen.write_text(
        json.dumps(
            {
                "policy": {
                    "permitted_use": "final_acceptance_only",
                    "development_use_allowed": False,
                },
                "reports": [],
            }
        ),
        encoding="utf-8",
    )


def test_repository_research_v2_evidence_is_intact() -> None:
    summary = verify_research_v2(REPOSITORY_ROOT)

    assert summary.experiments_verified == 5
    assert summary.artifacts_verified == 6
    assert summary.prepared_scenarios_verified == 6
    assert summary.scientific_status == "historical_unvalidated"


@pytest.mark.parametrize("newline", [b"\n", b"\r\n"])
def test_research_v2_verifies_both_git_checkout_formats(tmp_path: Path, newline: bytes) -> None:
    _copy_fixture(tmp_path)
    for path in tmp_path.rglob("*.json"):
        path.write_bytes(path.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", newline))

    assert verify_research_v2(tmp_path).experiments_verified == 5


def test_research_v2_verifier_rejects_report_tampering(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    report = tmp_path / "docs/research-v2/experiments/dev2-origin-diagnostic-v1.json"
    report.write_text(report.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="hash mismatch"):
        verify_research_v2(tmp_path)


def test_research_v2_verifier_rejects_sensitive_report_fields(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    report = tmp_path / "docs/research-v2/experiments/dev2-origin-diagnostic-v1.json"
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    payload["src_ip"] = "192.0.2.1"
    report.write_text(json.dumps(payload), encoding="utf-8")

    manifest_path = tmp_path / "configs/research-v2/evidence-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert isinstance(manifest, dict)
    experiments = manifest["experiments"]
    assert isinstance(experiments, list)
    origin_entry = next(
        item for item in experiments if item["experiment_id"] == "DEV2-ORIGIN-001"
    )
    assert isinstance(origin_entry, dict)
    origin_entry["report_sha256"] = _sha256(report)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="prohibited key"):
        verify_research_v2(tmp_path)


@pytest.mark.parametrize("relative", [
    "docs/../data/private.json", "../escape.json", "C:/private.json",
    "docs\\research-v2\\file.json", "/docs/file.json", "docs//file.json",
    ".git/config", "data/file.npz",
])
def test_research_v2_rejects_noncanonical_paths(tmp_path: Path, relative: str) -> None:
    with pytest.raises(ValueError, match="repository path"):
        _safe_path(tmp_path, relative)


@pytest.mark.parametrize("relative", ["extra.csv", "nested/extra.json"])
def test_research_v2_rejects_unbound_artifacts(tmp_path: Path, relative: str) -> None:
    _copy_fixture(tmp_path)
    extra = tmp_path / "docs/research-v2/experiments" / relative
    extra.parent.mkdir(exist_ok=True)
    extra.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="unbound files"):
        verify_research_v2(tmp_path)


@pytest.mark.parametrize(("field", "value", "message"), [
    ("scenario", "CTU-13 scenario 8", "undeclared scenarios"),
    ("scenario", "192.0.2.1", "undeclared scenarios"),
    ("family", "unreviewed", "undeclared families"),
    ("binary_label", 2.0, "must be binary"),
    ("binary_label", float("nan"), "invalid embedding"),
])
def test_research_v2_validates_embedding_content_even_if_rehashed(
    tmp_path: Path, field: str, value: object, message: str,
) -> None:
    _copy_fixture(tmp_path)
    manifest_path = tmp_path / "configs/research-v2/evidence-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entry = manifest["experiments"][0]["artifacts"][0]
    artifact = tmp_path / entry["path"]
    with np.load(artifact, allow_pickle=False) as archive:
        arrays = {key: archive[key] for key in archive.files}
    if arrays[field].dtype.kind == "U":
        arrays[field] = arrays[field].astype("U100")
    arrays[field][0] = value
    np.savez_compressed(artifact, **arrays)
    entry["sha256"] = _sha256(artifact)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        verify_research_v2(tmp_path)


def test_research_v2_rejects_unearned_scientific_status(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    path = tmp_path / "configs/research-v2/evidence-manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["scientific_status"] = "validated"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="incomplete scientific provenance"):
        verify_research_v2(tmp_path)
