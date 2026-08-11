from __future__ import annotations

import numpy as np
import pytest

from packages.features.registry import FEATURE_NAMES
from packages.features.research import (
    PORTABLE_FEATURE_NAMES,
    PORTABLE_NUMERICAL_CORE_FEATURE_NAMES,
    RUNTIME_ENRICHED_FEATURE_NAMES,
)
from training.data.models import CanonicalDataset, InputProvenance
from training.research.hybrid import run_held_family_hybrid_temporal


def _supervised_source(name: str, offset: float) -> CanonicalDataset:
    generator = np.random.default_rng(int(offset * 100) + 19)
    labels = np.asarray(["benign"] * 80 + ["alpha"] * 40 + ["beta"] * 40)
    portable = np.zeros((len(labels), len(PORTABLE_FEATURE_NAMES)), dtype=np.float64)
    core_indices = [
        PORTABLE_FEATURE_NAMES.index(item)
        for item in PORTABLE_NUMERICAL_CORE_FEATURE_NAMES
    ]
    portable[:80, core_indices] = generator.normal(offset, 0.2, size=(80, 9))
    portable[80:, core_indices] = generator.normal(offset + 2.0, 0.2, size=(80, 9))
    return CanonicalDataset(
        name=name,
        features=np.ones((len(labels), len(FEATURE_NAMES)), dtype=np.float64),
        labels=labels,
        raw_labels=labels.copy(),
        groups=np.full(len(labels), f"{name}-capture"),
        timestamps=np.full(len(labels), np.datetime64("NaT")),
        source_files=np.full(len(labels), f"{name}.csv"),
        raw_column_names=(),
        source_profiles=(),
        provenance=(InputProvenance(f"{name}.csv", len(labels), name * 16, None),),
        portable_features=portable,
    )


def _temporal_source(*, include_schema_b: bool = True) -> CanonicalDataset:
    generator = np.random.default_rng(91)
    labels = np.asarray(
        ["benign"] * 30
        + ["benign"] * 30
        + ["benign"] * 30
        + ["alpha"] * 20
        + ["beta"] * 10
        + ["benign"] * 30
        + ["alpha"] * 20
        + ["beta"] * 10
    )
    groups = np.asarray(
        ["benign-a"] * 30
        + ["benign-b"] * 30
        + ["attack-a"] * 60
        + ["attack-b"] * 60
    )
    enriched = generator.normal(
        0.0, 0.15, size=(len(labels), len(RUNTIME_ENRICHED_FEATURE_NAMES))
    )
    enriched[labels != "benign"] += 1.5
    portable = enriched[:, : len(PORTABLE_FEATURE_NAMES)]
    return CanonicalDataset(
        name="temporal",
        features=np.ones((len(labels), len(FEATURE_NAMES)), dtype=np.float64),
        labels=labels,
        raw_labels=labels.copy(),
        groups=groups,
        timestamps=np.datetime64("2020-01-01")
        + np.arange(len(labels)).astype("timedelta64[s]"),
        source_files=groups.copy(),
        raw_column_names=(),
        source_profiles=(),
        provenance=(InputProvenance("temporal.log", len(labels), "c" * 64, None),),
        portable_features=portable,
        runtime_enriched_features=enriched if include_schema_b else None,
    )


def test_hybrid_temporal_holds_families_and_calibration_groups_out() -> None:
    report = run_held_family_hybrid_temporal(
        {
            "first": _supervised_source("first", 0.0),
            "second": _supervised_source("second", 0.4),
        },
        "temporal",
        _temporal_source(),
        supervised_model_name="logistic_regression",
        max_rows_per_class=50,
        minimum_family_rows=5,
    )

    assert report["held_families"] == ["alpha", "beta"]
    assert len(report["runs"]) == 4
    assert report["feature_order"] == list(PORTABLE_NUMERICAL_CORE_FEATURE_NAMES) + list(
        RUNTIME_ENRICHED_FEATURE_NAMES[len(PORTABLE_FEATURE_NAMES) :]
    )
    for classifier in report["classifier_fits"]:
        assert classifier["held_family"] not in classifier["training_attack_families"]
        assert classifier["held_family_rows_excluded"] > 0
    for run in report["runs"]:
        assert run["fit_benign_group"] != run["calibration_benign_group"]
        assert set(run["test_groups"]).isdisjoint(
            {run["fit_benign_group"], run["calibration_benign_group"]}
        )
        assert run["signature_ablation"]["status"] == "not_evaluable"
        full = next(
            item for item in run["ablations"] if item["ablation"] == "full_hybrid"
        )
        assert full["calibration_direct_fpr"] <= 0.01
        assert full["calibration_review_rate"] <= 0.05
    assert "predictions" not in str(report)


def test_hybrid_temporal_requires_schema_b() -> None:
    with pytest.raises(ValueError, match="requires research Schema B"):
        run_held_family_hybrid_temporal(
            {
                "first": _supervised_source("first", 0.0),
                "second": _supervised_source("second", 0.4),
            },
            "temporal",
            _temporal_source(include_schema_b=False),
            supervised_model_name="logistic_regression",
            max_rows_per_class=50,
            minimum_family_rows=5,
        )
