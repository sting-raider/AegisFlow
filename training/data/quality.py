from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from typing import Any

import numpy as np
import pandas as pd

from packages.features.registry import FEATURE_NAMES, FEATURE_REGISTRY
from training.data.models import CanonicalDataset


@dataclass(frozen=True)
class QualityReport:
    dataset: str
    fingerprint: str
    rows: int
    duplicate_rows: int
    constant_columns: tuple[str, ...]
    missing_values: dict[str, int]
    infinite_values: dict[str, int]
    out_of_range_values: dict[str, int]
    raw_to_normalized_labels: dict[str, dict[str, int]]
    class_distribution: dict[str, int]
    identifier_columns: tuple[str, ...]
    suspiciously_predictive_columns: tuple[dict[str, Any], ...]
    adapter_notes: tuple[str, ...]
    warnings: tuple[str, ...]
    blocking_issues: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def quality_report(dataset: CanonicalDataset) -> QualityReport:
    frame = pd.DataFrame(dataset.features, columns=FEATURE_NAMES)
    combined = frame.copy()
    combined["__label"] = dataset.labels
    duplicate_rows = int(combined.duplicated().sum())
    constant_columns = tuple(
        name for name in FEATURE_NAMES if frame[name].nunique(dropna=False) <= 1
    )
    missing = {name: int(frame[name].isna().sum()) for name in FEATURE_NAMES}
    infinite = {
        name: int(np.isinf(frame[name].to_numpy(dtype=np.float64)).sum())
        for name in FEATURE_NAMES
    }
    out_of_range = {
        spec.name: int(
            ((frame[spec.name] < spec.minimum) | (frame[spec.name] > spec.maximum)).sum()
        )
        for spec in FEATURE_REGISTRY
    }
    normalization: dict[str, dict[str, int]] = defaultdict(dict)
    for raw, normalized in zip(dataset.raw_labels, dataset.labels, strict=True):
        bucket = normalization[str(raw)]
        label = str(normalized)
        bucket[label] = bucket.get(label, 0) + 1
    identifiers = tuple(
        sorted(profile.name for profile in dataset.source_profiles if profile.identifier_like)
    )
    suspicious = tuple(
        {
            "column": profile.name,
            "label_purity": round(profile.label_purity, 6),
            "unique_ratio": round(profile.unique_ratio, 6),
            "reason": "near-perfect label association",
        }
        for profile in dataset.source_profiles
        if profile.label_purity >= 0.98 and 0.001 <= profile.unique_ratio <= 0.95
    )
    issues: list[str] = []
    warnings: list[str] = []
    if duplicate_rows:
        warnings.append(f"{duplicate_rows} duplicate canonical rows")
    if constant_columns:
        warnings.append("canonical features contain constant columns")
    if sum(missing.values()):
        issues.append("canonical features contain missing values")
    if sum(infinite.values()):
        issues.append("canonical features contain infinite values")
    if sum(out_of_range.values()):
        issues.append("canonical features contain values outside the feature registry")
    if len(set(dataset.labels)) < 2:
        issues.append("dataset has fewer than two normalized classes")
    if suspicious:
        warnings.append("source columns show suspiciously predictive label association")
    return QualityReport(
        dataset=dataset.name,
        fingerprint=dataset.fingerprint,
        rows=dataset.row_count,
        duplicate_rows=duplicate_rows,
        constant_columns=constant_columns,
        missing_values=missing,
        infinite_values=infinite,
        out_of_range_values=out_of_range,
        raw_to_normalized_labels=dict(normalization),
        class_distribution=dict(sorted(Counter(map(str, dataset.labels)).items())),
        identifier_columns=identifiers,
        suspiciously_predictive_columns=suspicious,
        adapter_notes=dataset.adapter_notes,
        warnings=tuple(warnings),
        blocking_issues=tuple(issues),
    )


def train_test_overlap(
    train_features: np.ndarray, test_features: np.ndarray
) -> dict[str, int | float]:
    train_hashes = set(
        pd.util.hash_pandas_object(
            pd.DataFrame(train_features, columns=FEATURE_NAMES), index=False
        ).to_numpy(dtype=np.uint64)
    )
    test_values = pd.util.hash_pandas_object(
        pd.DataFrame(test_features, columns=FEATURE_NAMES), index=False
    ).to_numpy(dtype=np.uint64)
    overlap = sum(value in train_hashes for value in test_values)
    return {
        "overlap_rows": int(overlap),
        "test_rows": len(test_values),
        "overlap_fraction": float(overlap / max(len(test_values), 1)),
    }


def feature_drift(reference: CanonicalDataset, comparison: CanonicalDataset) -> dict[str, Any]:
    features: dict[str, dict[str, float | int | None]] = {}
    for index, name in enumerate(FEATURE_NAMES):
        left = reference.features[:, index]
        right = comparison.features[:, index]
        left_finite = left[np.isfinite(left)]
        right_finite = right[np.isfinite(right)]
        if not len(left_finite) or not len(right_finite):
            shift: float | None = None
            left_mean: float | None = None
            right_mean: float | None = None
        else:
            left_mean = float(np.mean(left_finite))
            right_mean = float(np.mean(right_finite))
            pooled = max(float(np.sqrt((np.var(left_finite) + np.var(right_finite)) / 2)), 1e-12)
            shift = abs(right_mean - left_mean) / pooled
        features[name] = {
            "reference_mean": left_mean,
            "comparison_mean": right_mean,
            "standardized_mean_shift": shift,
            "reference_missing": int(len(left) - len(left_finite)),
            "comparison_missing": int(len(right) - len(right_finite)),
        }
    return {
        "reference": reference.name,
        "comparison": comparison.name,
        "reference_fingerprint": reference.fingerprint,
        "comparison_fingerprint": comparison.fingerprint,
        "features": features,
    }
