from __future__ import annotations

import numpy as np

from packages.features.registry import FEATURE_NAMES
from packages.features.research import (
    PORTABLE_FEATURE_NAMES,
    PORTABLE_NUMERICAL_CORE_FEATURE_NAMES,
)
from training.data.models import CanonicalDataset, InputProvenance
from training.research.anomaly import run_cross_environment_anomaly_baselines
from training.research.baselines import run_cross_environment_supervised


def _source(name: str, offset: float) -> CanonicalDataset:
    rows = 160
    generator = np.random.default_rng(int(offset * 100) + 17)
    labels = np.asarray(["benign"] * 80 + ["attack"] * 80)
    portable = np.zeros((rows, len(PORTABLE_FEATURE_NAMES)), dtype=np.float64)
    core_indices = [
        PORTABLE_FEATURE_NAMES.index(item)
        for item in PORTABLE_NUMERICAL_CORE_FEATURE_NAMES
    ]
    portable[:80, core_indices] = generator.normal(
        offset, 0.2, size=(80, len(core_indices))
    )
    portable[80:, core_indices] = generator.normal(
        offset + 2.0, 0.2, size=(80, len(core_indices))
    )
    return CanonicalDataset(
        name=name,
        features=np.ones((rows, len(FEATURE_NAMES)), dtype=np.float64),
        labels=labels,
        raw_labels=labels.copy(),
        groups=np.full(rows, f"{name}-capture"),
        timestamps=np.full(rows, np.datetime64("NaT")),
        source_files=np.full(rows, f"{name}.csv"),
        raw_column_names=(),
        source_profiles=(),
        provenance=(InputProvenance(f"{name}.csv", rows, name * 16, None),),
        portable_features=portable,
    )


def test_cross_environment_supervised_baseline_is_deterministic_and_aggregate_only() -> None:
    datasets = {
        "first": _source("first", 0.0),
        "second": _source("second", 0.5),
        "third": _source("third", 1.0),
    }

    report = run_cross_environment_supervised(
        datasets,
        models=("logistic_regression",),
        max_rows_per_class=50,
    )
    repeated = run_cross_environment_supervised(
        datasets,
        models=("logistic_regression",),
        max_rows_per_class=50,
    )

    assert report["status"] == "development_evidence_only_no_candidate_selected"
    assert report["feature_order"] == list(PORTABLE_NUMERICAL_CORE_FEATURE_NAMES)
    assert len(report["rotations"]) == 3
    assert report["summary"]["logistic_regression"]["rotations"] == 3
    assert [item["sampled_indices_sha256"] for item in report["sources"]] == [
        item["sampled_indices_sha256"] for item in repeated["sources"]
    ]
    assert "predictions" not in str(report)


def test_three_way_anomaly_baseline_keeps_fit_calibration_and_test_distinct() -> None:
    datasets = {
        "first": _source("first", 0.0),
        "second": _source("second", 0.5),
        "third": _source("third", 1.0),
    }

    report = run_cross_environment_anomaly_baselines(
        datasets,
        models=("isolation_forest",),
        max_rows_per_class=50,
    )

    assert len(report["runs"]) == 6
    assert report["summary"]["isolation_forest"]["completed_runs"] == 6
    for run in report["runs"]:
        assert len(
            {run["fit_source"], run["calibration_source"], run["testing_source"]}
        ) == 3
        assert run["status"] == "complete"
        assert run["per_family"]["attack"]["rows"] > 0
