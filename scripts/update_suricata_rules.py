from __future__ import annotations

import argparse
import hashlib
import os
import tempfile
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

MAX_RULESET_BYTES = 64 * 1024 * 1024


def update(url: str, expected_sha256: str, destination: Path) -> Path:
    if len(expected_sha256) != 64 or any(ch not in "0123456789abcdef" for ch in expected_sha256):
        raise ValueError("--sha256 must be a lowercase SHA-256 digest")
    destination = destination.resolve()
    allowed_root = Path("configs/suricata/rules").resolve()
    if destination.parent != allowed_root:
        raise ValueError("rules may be written only to configs/suricata/rules")
    parsed_url = urlparse(url)
    if parsed_url.scheme != "https" or not parsed_url.hostname:
        raise ValueError("ruleset URL must use HTTPS")
    request = urllib.request.Request(url, headers={"User-Agent": "AegisFlow-rule-updater/1"})
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".rules-", dir=destination.parent)
    temporary = Path(temporary_name)
    digest = hashlib.sha256()
    total = 0
    try:
        with (
            os.fdopen(descriptor, "wb") as output,
            urllib.request.urlopen(request, timeout=30) as response,
        ):
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_RULESET_BYTES:
                    raise ValueError("ruleset exceeds the 64 MiB safety limit")
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        if digest.hexdigest() != expected_sha256:
            raise ValueError("ruleset checksum mismatch")
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def main() -> None:
    parser = argparse.ArgumentParser(description="Download a checksum-pinned Suricata ruleset")
    parser.add_argument("--url", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument(
        "--destination",
        type=Path,
        default=Path("configs/suricata/rules/community.rules"),
    )
    args = parser.parse_args()
    print(update(args.url, args.sha256, args.destination))


if __name__ == "__main__":
    main()
