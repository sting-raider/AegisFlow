from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

MAX_DATASET_BYTES = 20 * 1024 * 1024 * 1024


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(
    url: str,
    destination: Path,
    expected_sha256: str,
    license_name: str,
    *,
    dataset_name: str,
    source_page: str,
    capture_boundaries: str,
    label_mapping: dict[str, str],
    transformation_history: list[str],
    expected_size: int | None = None,
    max_bytes: int = MAX_DATASET_BYTES,
) -> None:
    parsed_url = urlparse(url)
    if parsed_url.scheme != "https" or not parsed_url.hostname:
        raise ValueError("dataset URL must use HTTPS")
    if len(expected_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in expected_sha256
    ):
        raise ValueError("expected SHA-256 must be a lowercase digest")
    if max_bytes < 1 or (expected_size is not None and expected_size > max_bytes):
        raise ValueError("dataset size exceeds the configured download limit")
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_suffix(f"{destination.suffix}.part")
    offset = partial.stat().st_size if partial.exists() else 0
    request = urllib.request.Request(url, headers={"Range": f"bytes={offset}-"} if offset else {})
    with urllib.request.urlopen(request, timeout=60) as response:
        status = getattr(response, "status", 200)
        if offset and status != 206:
            offset = 0
        mode = "ab" if offset and status == 206 else "wb"
        downloaded = offset if mode == "ab" else 0
        with partial.open(mode) as output:
            while chunk := response.read(1024 * 1024):
                downloaded += len(chunk)
                if downloaded > max_bytes:
                    raise RuntimeError("dataset exceeds the configured download limit")
                output.write(chunk)
    if expected_size is not None and partial.stat().st_size != expected_size:
        raise RuntimeError(
            f"size mismatch for {partial}: expected {expected_size}, got {partial.stat().st_size}"
        )
    actual_sha256 = sha256_file(partial)
    if actual_sha256 != expected_sha256:
        raise RuntimeError(
            f"checksum mismatch for {partial}: expected {expected_sha256}, got {actual_sha256}"
        )
    partial.replace(destination)
    manifest = {
        "schema_version": "1.0.0",
        "dataset_name": dataset_name,
        "source_url": url,
        "source_page": source_page,
        "retrieved_at": datetime.now(UTC).isoformat(),
        "license": license_name,
        "expected_filename": destination.name,
        "expected_size_bytes": expected_size,
        "expected_sha256": expected_sha256,
        "capture_boundaries": capture_boundaries,
        "label_mapping": label_mapping,
        "transformation_history": transformation_history,
        "actual_filename": destination.name,
        "size_bytes": destination.stat().st_size,
        "sha256": actual_sha256,
    }
    manifest_path = destination.with_suffix(f"{destination.suffix}.manifest.json")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".dataset-manifest-", dir=destination.parent
    )
    temporary_manifest = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(manifest, output, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_manifest, manifest_path)
    finally:
        temporary_manifest.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Resume a dataset download and accept it only after SHA-256 verification."
    )
    parser.add_argument("--url", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--license", required=True, dest="license_name")
    parser.add_argument("--dataset-name", required=True)
    parser.add_argument("--source-page", required=True)
    parser.add_argument("--capture-boundaries", required=True)
    parser.add_argument("--label-mapping", type=Path, required=True)
    parser.add_argument("--transformation", action="append", default=[])
    parser.add_argument("--expected-size", type=int)
    parser.add_argument("--max-bytes", type=int, default=MAX_DATASET_BYTES)
    args = parser.parse_args()
    decoded_mapping = json.loads(args.label_mapping.read_text(encoding="utf-8"))
    if not isinstance(decoded_mapping, dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in decoded_mapping.items()
    ):
        raise ValueError("label mapping must be a JSON object of string pairs")
    download(
        args.url,
        args.output,
        args.sha256,
        args.license_name,
        dataset_name=args.dataset_name,
        source_page=args.source_page,
        capture_boundaries=args.capture_boundaries,
        label_mapping=decoded_mapping,
        transformation_history=args.transformation,
        expected_size=args.expected_size,
        max_bytes=args.max_bytes,
    )


if __name__ == "__main__":
    main()
