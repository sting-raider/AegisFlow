from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path

import pytest

from scripts.download_dataset import download


class _Response(io.BytesIO):
    status = 200

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def test_dataset_download_requires_https_and_lowercase_checksum(tmp_path: Path) -> None:
    destination = tmp_path / "dataset.csv"
    with pytest.raises(ValueError, match="lowercase"):
        download(
            "https://datasets.invalid/file.csv",
            destination,
            "not-a-digest",
            "fixture",
            dataset_name="fixture",
            source_page="https://datasets.invalid/fixture",
            capture_boundaries="fixture groups",
            label_mapping={"normal": "benign"},
            transformation_history=["none"],
        )
    with pytest.raises(ValueError, match="HTTPS"):
        download(
            "http://datasets.invalid/file.csv",
            destination,
            "0" * 64,
            "fixture",
            dataset_name="fixture",
            source_page="https://datasets.invalid/fixture",
            capture_boundaries="fixture groups",
            label_mapping={"normal": "benign"},
            transformation_history=["none"],
        )


def test_dataset_download_rejects_declared_oversize(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="exceeds"):
        download(
            "https://datasets.invalid/file.csv",
            tmp_path / "dataset.csv",
            "0" * 64,
            "fixture",
            expected_size=11,
            max_bytes=10,
            dataset_name="fixture",
            source_page="https://datasets.invalid/fixture",
            capture_boundaries="fixture groups",
            label_mapping={"normal": "benign"},
            transformation_history=["none"],
        )


def test_dataset_download_writes_verified_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    content = b"duration,label\n1,normal\n"
    monkeypatch.setattr(
        "urllib.request.urlopen", lambda *_args, **_kwargs: _Response(content)
    )
    destination = tmp_path / "dataset.csv"
    digest = hashlib.sha256(content).hexdigest()
    download(
        "https://datasets.invalid/file.csv",
        destination,
        digest,
        "fixture-license",
        dataset_name="fixture",
        source_page="https://datasets.invalid/fixture",
        capture_boundaries="fixture groups",
        label_mapping={"normal": "benign"},
        transformation_history=["none"],
        expected_size=len(content),
    )
    assert destination.read_bytes() == content
    manifest = json.loads(
        destination.with_suffix(".csv.manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["expected_sha256"] == digest
    assert manifest["label_mapping"] == {"normal": "benign"}
