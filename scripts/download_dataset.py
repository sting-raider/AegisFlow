from __future__ import annotations

import argparse
import hashlib
import json
import urllib.request
from datetime import UTC, datetime
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(url: str, destination: Path, expected_sha256: str, license_name: str) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_suffix(f"{destination.suffix}.part")
    offset = partial.stat().st_size if partial.exists() else 0
    request = urllib.request.Request(url, headers={"Range": f"bytes={offset}-"} if offset else {})
    with urllib.request.urlopen(request, timeout=60) as response:
        status = getattr(response, "status", 200)
        if offset and status != 206:
            offset = 0
        mode = "ab" if offset and status == 206 else "wb"
        with partial.open(mode) as output:
            while chunk := response.read(1024 * 1024):
                output.write(chunk)
    actual_sha256 = sha256_file(partial)
    if actual_sha256.lower() != expected_sha256.lower():
        raise RuntimeError(
            f"checksum mismatch for {partial}: expected {expected_sha256}, got {actual_sha256}"
        )
    partial.replace(destination)
    manifest = {
        "source_url": url,
        "retrieved_at": datetime.now(UTC).isoformat(),
        "license": license_name,
        "filename": destination.name,
        "size_bytes": destination.stat().st_size,
        "sha256": actual_sha256,
    }
    destination.with_suffix(f"{destination.suffix}.manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Resume a dataset download and accept it only after SHA-256 verification."
    )
    parser.add_argument("--url", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--license", required=True, dest="license_name")
    args = parser.parse_args()
    download(args.url, args.output, args.sha256, args.license_name)


if __name__ == "__main__":
    main()
