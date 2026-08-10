from __future__ import annotations

import json
from pathlib import Path

from training.data.models import InputProvenance


def frozen_source_hashes(manifest_path: Path) -> set[str]:
    decoded = json.loads(manifest_path.read_text(encoding="utf-8"))
    reports = decoded.get("reports")
    if not isinstance(reports, list):
        raise ValueError("frozen evidence manifest reports must be an array")
    hashes: set[str] = set()
    for report in reports:
        if not isinstance(report, dict) or not isinstance(report.get("source_files"), list):
            raise ValueError("frozen evidence source_files must be arrays")
        for source in report["source_files"]:
            if not isinstance(source, dict) or not isinstance(source.get("sha256"), str):
                raise ValueError("frozen evidence source fingerprint is invalid")
            hashes.add(source["sha256"])
    return hashes


def assert_development_only(
    provenance: tuple[InputProvenance, ...], frozen_manifest: Path
) -> None:
    frozen = frozen_source_hashes(frozen_manifest)
    conflicts = sorted(item.filename for item in provenance if item.sha256 in frozen)
    if conflicts:
        raise ValueError(
            "development preparation refused frozen-final source hashes: "
            + ", ".join(conflicts)
        )
