from __future__ import annotations

import argparse
import json
import os
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Any, cast

from packages.model_bundle import load_production_bundle
from packages.model_bundle.bundle import sha256_file
from training.data.adapters import DatasetKind, load_dataset
from training.data.hybrid_evaluate import evaluate_hybrid_gate
from training.data.quality import feature_drift, quality_report, train_test_overlap
from training.data.splits import SplitStrategy, create_split, cross_dataset_split


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(payload, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run reproducible quality, leakage, split, and dataset evaluation gates"
    )
    choices = ["cic_ids2017", "cse_cic_ids2018", "unsw_nb15", "nfstream_csv"]
    parser.add_argument("--dataset", choices=choices, required=True)
    parser.add_argument("--input", type=Path, action="append", required=True)
    parser.add_argument("--label-column")
    parser.add_argument("--group-column")
    parser.add_argument("--timestamp-column")
    parser.add_argument(
        "--split",
        choices=["time", "capture_day", "source_file", "leave_family_out"],
        default="source_file",
    )
    parser.add_argument("--held-out-family")
    parser.add_argument("--test-fraction", type=float, default=0.2)
    parser.add_argument("--cross-dataset", choices=choices)
    parser.add_argument("--cross-input", type=Path, action="append")
    parser.add_argument("--cross-label-column")
    parser.add_argument("--max-rows", type=int, default=5_000_000)
    parser.add_argument("--model-registry", type=Path, default=Path("models/registry"))
    parser.add_argument("--model-name", default="aegisflow-smoke")
    parser.add_argument("--output", type=Path, default=Path("reports/dataset-evaluation.json"))
    args = parser.parse_args()

    dataset = load_dataset(
        cast(DatasetKind, args.dataset),
        args.input,
        label_column=args.label_column,
        group_column=args.group_column,
        timestamp_column=args.timestamp_column,
        max_rows=args.max_rows,
    )
    quality = quality_report(dataset)
    payload: dict[str, Any] = {
        "schema_version": "1.1.0",
        "dataset": dataset.name,
        "fingerprint": dataset.fingerprint,
        "provenance": [asdict(item) for item in dataset.provenance],
        "quality": quality.as_dict(),
        "adapter_notes": list(dataset.adapter_notes),
    }
    if quality.blocking_issues:
        payload["evaluation"] = {"status": "blocked", "reasons": quality.blocking_issues}
        _atomic_json(args.output, payload)
        raise SystemExit(f"quality gate blocked evaluation; report written to {args.output}")

    if args.cross_dataset:
        if not args.cross_input:
            parser.error("--cross-input is required with --cross-dataset")
        comparison = load_dataset(
            cast(DatasetKind, args.cross_dataset),
            args.cross_input,
            label_column=args.cross_label_column,
            max_rows=args.max_rows,
        )
        comparison_quality = quality_report(comparison)
        payload["cross_quality"] = comparison_quality.as_dict()
        payload["cross_provenance"] = [asdict(item) for item in comparison.provenance]
        payload["evaluation_mode"] = (
            "official_published_partition"
            if dataset.name == comparison.name
            else "cross_dataset"
        )
        if comparison_quality.blocking_issues:
            payload["evaluation"] = {
                "status": "blocked",
                "reasons": comparison_quality.blocking_issues,
            }
            _atomic_json(args.output, payload)
            raise SystemExit(
                f"cross-dataset quality gate blocked evaluation; report written to {args.output}"
            )
        train, test = cross_dataset_split(dataset, comparison)
        payload["feature_drift"] = feature_drift(dataset, comparison)
        payload["cross_dataset_overlap"] = train_test_overlap(dataset.features, comparison.features)
        payload["cross_adapter_notes"] = list(comparison.adapter_notes)
        deployed_bundle = load_production_bundle(args.model_registry, args.model_name)
        payload["evaluation_bundle"] = {
            "model_name": args.model_name,
            "version": deployed_bundle.version,
            "bundle_schema_version": deployed_bundle.manifest.get("bundle_schema_version"),
            "bundle_digest": sha256_file(deployed_bundle.root / "checksums.sha256"),
        }
        payload["evaluation"] = evaluate_hybrid_gate(
            dataset, comparison, train, test, deployed_bundle
        )
    else:
        split = create_split(
            dataset,
            cast(SplitStrategy, args.split),
            test_fraction=args.test_fraction,
            held_out_family=args.held_out_family,
        )
        payload["split"] = split.manifest()
        deployed_bundle = load_production_bundle(args.model_registry, args.model_name)
        payload["evaluation_bundle"] = {
            "model_name": args.model_name,
            "version": deployed_bundle.version,
            "bundle_schema_version": deployed_bundle.manifest.get("bundle_schema_version"),
            "bundle_digest": sha256_file(deployed_bundle.root / "checksums.sha256"),
        }
        payload["evaluation"] = evaluate_hybrid_gate(
            dataset,
            dataset,
            split.train_indices,
            split.test_indices,
            deployed_bundle,
        )
    _atomic_json(args.output, payload)
    print(args.output.resolve())


if __name__ == "__main__":
    main()
