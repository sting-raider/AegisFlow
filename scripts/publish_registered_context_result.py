"""Publish an already verified DEV2-CONTEXT-001 report byte-for-byte."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from scripts.verify_registered_context_result import (
    REPORT_SHA256,
    validate_local_evidence,
    validate_report,
)
from training.v2.provenance import read_object, sha256_file


def publish(root: Path, source: Path, destination: Path) -> None:
    if destination.exists():
        raise FileExistsError(f"refusing to overwrite published context result: {destination}")
    if sha256_file(source) != REPORT_SHA256:
        raise ValueError("context source report bytes differ from registered execution")
    report = read_object(source)
    validate_report(root, report)
    validate_local_evidence(root, source.parent, report)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as input_stream, destination.open("xb") as output_stream:
        shutil.copyfileobj(input_stream, output_stream)
    if sha256_file(destination) != REPORT_SHA256:
        raise ValueError("published context report copy changed bytes")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    args = parser.parse_args()
    publish(Path(__file__).resolve().parents[1], args.source, args.destination)
    print(f"published context result: {args.destination}")


if __name__ == "__main__":
    main()
