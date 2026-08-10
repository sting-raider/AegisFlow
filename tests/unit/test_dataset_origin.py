from __future__ import annotations

from dataclasses import replace

import numpy as np
import pytest

from packages.features.research import PORTABLE_FEATURE_NAMES
from training.data.models import CanonicalDataset, InputProvenance
from training.data.origin import evaluate_dataset_origin


def _dataset(name: str, matrix: np.ndarray) -> CanonicalDataset:
    rows = len(matrix)
    return CanonicalDataset(
        name=name,
        features=np.ones((rows, 18), dtype=np.float64),
        labels=np.full(rows, "benign"),
        raw_labels=np.full(rows, "Benign"),
        groups=np.full(rows, name),
        timestamps=np.full(rows, np.datetime64("NaT")),
        source_files=np.full(rows, f"{name}.csv"),
        raw_column_names=(),
        source_profiles=(),
        provenance=(InputProvenance(f"{name}.csv", rows, name * 32, None),),
        portable_features=matrix,
    )


def test_origin_diagnostic_blocks_an_obvious_dataset_shortcut() -> None:
    generator = np.random.default_rng(17)
    first = generator.normal(0.0, 0.05, size=(400, len(PORTABLE_FEATURE_NAMES)))
    second = generator.normal(5.0, 0.05, size=(400, len(PORTABLE_FEATURE_NAMES)))

    report = evaluate_dataset_origin(
        [_dataset("first", first), _dataset("second", second)],
        max_rows_per_source=300,
    )

    assert report["challenger_selection_blocked"] is True
    assert report["full_schema_a"]["balanced_accuracy"] > 0.99
    assert report["sources"][0]["sampled_rows"] == 300
    assert "protocol_tcp" in report["categorical_ablation"]["removed_features"]


def test_origin_diagnostic_rejects_missing_schema_and_duplicate_source_ids() -> None:
    matrix = np.ones((120, len(PORTABLE_FEATURE_NAMES)), dtype=np.float64)
    dataset = _dataset("first", matrix)
    without_schema = replace(dataset, portable_features=None)

    with pytest.raises(ValueError, match="Schema A"):
        evaluate_dataset_origin(
            [without_schema, dataset], source_ids=["missing", "present"]
        )
    with pytest.raises(ValueError, match="unique"):
        evaluate_dataset_origin([dataset, dataset], source_ids=["same", "same"])
