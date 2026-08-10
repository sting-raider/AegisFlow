from __future__ import annotations

import argparse
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from training.data.adapters import DatasetKind, load_dataset
from training.data.development import assert_development_only
from training.data.origin import evaluate_dataset_origin


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
        description="Measure how readily research Schema A identifies source datasets"
    )
    parser.add_argument(
        "--source",
        nargs=3,
        action="append",
        metavar=("SOURCE_ID", "DATASET_KIND", "PATH"),
        required=True,
    )
    parser.add_argument("--max-rows-per-source", type=int, default=50_000)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--frozen-manifest",
        type=Path,
        default=Path("configs/evaluation/frozen-evidence-v1.json"),
    )
    args = parser.parse_args()
    grouped: dict[str, tuple[DatasetKind, list[Path]]] = {}
    for source_id, dataset_kind, path in args.source:
        kind = cast(DatasetKind, dataset_kind)
        existing = grouped.get(source_id)
        if existing is not None and existing[0] != kind:
            raise ValueError(f"source {source_id} cannot mix dataset kinds")
        if existing is None:
            grouped[source_id] = (kind, [Path(path)])
        else:
            existing[1].append(Path(path))
    datasets = []
    source_ids = []
    for source_id, (dataset_kind, paths) in grouped.items():
        dataset = load_dataset(dataset_kind, paths)
        assert_development_only(dataset.provenance, args.frozen_manifest)
        datasets.append(dataset)
        source_ids.append(source_id)
    report = evaluate_dataset_origin(
        datasets,
        source_ids=source_ids,
        max_rows_per_source=args.max_rows_per_source,
    )
    report["generated_at"] = datetime.now(UTC).isoformat()
    _atomic_json(args.output, report)
    print(args.output.resolve())


if __name__ == "__main__":
    main()
