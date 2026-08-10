from __future__ import annotations

import argparse
import json
import os
import tempfile
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from packages.features.research import (
    PORTABLE_SCHEMA_VERSION,
    TEMPORAL_SCHEMA_VERSION,
)
from training.data.adapters import DatasetKind, load_dataset
from training.data.development import assert_development_only
from training.data.quality import quality_report


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            json.dump(payload, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prepare a sanitized development-only dataset quality report"
    )
    parser.add_argument(
        "--dataset",
        choices=[
            "cic_ids2017",
            "cse_cic_ids2018",
            "hikari2021",
            "unsw_nb15",
            "nfstream_csv",
        ],
        required=True,
    )
    parser.add_argument("--input", type=Path, action="append", required=True)
    parser.add_argument("--label-column")
    parser.add_argument("--group-column")
    parser.add_argument("--timestamp-column")
    parser.add_argument("--max-rows", type=int, default=5_000_000)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--frozen-manifest",
        type=Path,
        default=Path("configs/evaluation/frozen-evidence-v1.json"),
    )
    args = parser.parse_args()
    dataset = load_dataset(
        cast(DatasetKind, args.dataset),
        args.input,
        label_column=args.label_column,
        group_column=args.group_column,
        timestamp_column=args.timestamp_column,
        max_rows=args.max_rows,
    )
    assert_development_only(dataset.provenance, args.frozen_manifest)
    quality = quality_report(dataset)
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "permitted_use": "development_fit_calibration_and_model_selection_only",
        "dataset": dataset.name,
        "dataset_fingerprint": dataset.fingerprint,
        "provenance": [asdict(item) for item in dataset.provenance],
        "quality": quality.as_dict(),
        "adapter_notes": list(dataset.adapter_notes),
        "research_features": {
            "schema_a_version": PORTABLE_SCHEMA_VERSION,
            "schema_a_rows": (
                len(dataset.portable_features)
                if dataset.portable_features is not None
                else 0
            ),
            "schema_b_version": TEMPORAL_SCHEMA_VERSION,
            "schema_b_rows": (
                len(dataset.runtime_enriched_features)
                if dataset.runtime_enriched_features is not None
                else 0
            ),
            "notes": list(dataset.research_feature_notes),
        },
    }
    _atomic_json(args.output, payload)
    if quality.blocking_issues:
        raise SystemExit(
            f"development quality gate failed; sanitized report written to {args.output}"
        )
    print(args.output.resolve())


if __name__ == "__main__":
    main()
