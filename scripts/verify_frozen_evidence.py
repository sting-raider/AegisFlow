from __future__ import annotations

import argparse
import json
from pathlib import Path

from training.evidence.frozen import (
    FrozenEvidenceError,
    evaluation_config_sha256,
    verify_frozen_evidence,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fail closed if frozen final-evaluation evidence or policy changed"
    )
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("configs/evaluation/frozen-evidence-v1.json"),
    )
    parser.add_argument(
        "--print-config-digests",
        action="store_true",
        help="Print canonical configuration digests while authoring a reviewed manifest",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    manifest_path = args.manifest
    if not manifest_path.is_absolute():
        manifest_path = root / manifest_path

    if args.print_config_digests:
        decoded = json.loads(manifest_path.read_text(encoding="utf-8"))
        for entry in decoded["reports"]:
            report = json.loads((root / entry["path"]).read_text(encoding="utf-8"))
            print(f"{entry['id']} {evaluation_config_sha256(report)}")
        return

    try:
        summary = verify_frozen_evidence(manifest_path, repository_root=root)
    except FrozenEvidenceError as error:
        raise SystemExit(f"frozen evidence verification failed: {error}") from error
    print(
        f"verified {summary.reports_verified} frozen reports and "
        f"{summary.source_fingerprints_verified} source fingerprints; "
        f"permitted_use={summary.permitted_use}"
    )


if __name__ == "__main__":
    main()
