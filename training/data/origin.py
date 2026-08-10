from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
)
from sklearn.model_selection import train_test_split

from packages.features.research import PORTABLE_FEATURE_NAMES, PORTABLE_SCHEMA_VERSION
from training.data.models import CanonicalDataset
from training.features import RobustResearchPreprocessor

ORIGIN_DIAGNOSTIC_SEED = 431
HIGH_ORIGIN_ACCURACY = 0.90


def _deduplicated_sample(
    matrix: np.ndarray, *, limit: int, seed: int
) -> tuple[np.ndarray, int]:
    unique = np.unique(matrix, axis=0)
    if len(unique) <= limit:
        return unique, len(unique)
    generator = np.random.default_rng(seed)
    indices = np.sort(generator.choice(len(unique), size=limit, replace=False))
    return unique[indices], len(unique)


def _evaluate_view(
    matrix: np.ndarray,
    origins: np.ndarray,
    feature_names: tuple[str, ...],
    selected: np.ndarray,
    *,
    seed: int,
    test_size: float,
) -> dict[str, Any]:
    indices = np.arange(len(matrix))
    train, test = train_test_split(
        indices,
        test_size=test_size,
        random_state=seed,
        stratify=origins,
    )
    selected_names = tuple(
        name for name, keep in zip(feature_names, selected, strict=True) if keep
    )
    preprocessor = RobustResearchPreprocessor(selected_names)
    training = preprocessor.fit_transform(matrix[train][:, selected])
    testing = preprocessor.transform(matrix[test][:, selected])
    classifier = LogisticRegression(
        class_weight="balanced",
        max_iter=1_500,
        random_state=seed,
    ).fit(training, origins[train])
    predictions = classifier.predict(testing)
    labels = classifier.classes_.astype(str)
    coefficient_magnitude = np.max(np.abs(classifier.coef_), axis=0)
    ranked = np.argsort(coefficient_magnitude)[::-1][: min(10, len(selected_names))]
    return {
        "feature_count": len(selected_names),
        "feature_order": list(selected_names),
        "train_rows": len(train),
        "test_rows": len(test),
        "accuracy": float(accuracy_score(origins[test], predictions)),
        "balanced_accuracy": float(
            balanced_accuracy_score(origins[test], predictions)
        ),
        "macro_f1": float(f1_score(origins[test], predictions, average="macro")),
        "confusion_labels": labels.tolist(),
        "confusion_matrix": confusion_matrix(
            origins[test], predictions, labels=labels
        ).tolist(),
        "top_absolute_coefficients": [
            {
                "feature": selected_names[index],
                "magnitude": float(coefficient_magnitude[index]),
            }
            for index in ranked
        ],
        "preprocessing": preprocessor.manifest(),
    }


def evaluate_dataset_origin(
    datasets: Sequence[CanonicalDataset],
    *,
    source_ids: Sequence[str] | None = None,
    max_rows_per_source: int = 50_000,
    seed: int = ORIGIN_DIAGNOSTIC_SEED,
    test_size: float = 0.25,
    high_accuracy_threshold: float = HIGH_ORIGIN_ACCURACY,
) -> dict[str, Any]:
    if len(datasets) < 2:
        raise ValueError("origin diagnostic requires at least two datasets")
    if max_rows_per_source < 100:
        raise ValueError("origin diagnostic requires at least 100 rows per source")
    if not 0.0 < test_size < 1.0:
        raise ValueError("test_size must be within (0, 1)")
    ids = list(source_ids or [dataset.name for dataset in datasets])
    if len(ids) != len(datasets) or len(set(ids)) != len(ids):
        raise ValueError("source IDs must be unique and align with datasets")

    sampled: list[np.ndarray] = []
    origin_labels: list[np.ndarray] = []
    source_summary: list[dict[str, Any]] = []
    for offset, (source_id, dataset) in enumerate(zip(ids, datasets, strict=True)):
        if dataset.portable_features is None:
            raise ValueError(f"source {source_id} does not provide research Schema A")
        selected, unique_rows = _deduplicated_sample(
            dataset.portable_features,
            limit=max_rows_per_source,
            seed=seed + offset,
        )
        if len(selected) < 2:
            raise ValueError(f"source {source_id} has insufficient unique Schema A rows")
        sampled.append(selected)
        origin_labels.append(np.full(len(selected), source_id, dtype=object))
        source_summary.append(
            {
                "source_id": source_id,
                "dataset": dataset.name,
                "dataset_fingerprint": dataset.fingerprint,
                "input_rows": dataset.row_count,
                "unique_schema_a_rows": unique_rows,
                "sampled_rows": len(selected),
                "provenance_sha256": [item.sha256 for item in dataset.provenance],
            }
        )

    matrix = np.vstack(sampled)
    origins = np.concatenate(origin_labels).astype(str)
    full_mask = np.ones(len(PORTABLE_FEATURE_NAMES), dtype=bool)
    categorical_mask = np.asarray(
        [
            name.startswith(("protocol_", "port_", "service_"))
            or name == "destination_port_missing"
            for name in PORTABLE_FEATURE_NAMES
        ]
    )
    full = _evaluate_view(
        matrix,
        origins,
        PORTABLE_FEATURE_NAMES,
        full_mask,
        seed=seed,
        test_size=test_size,
    )
    ablated = _evaluate_view(
        matrix,
        origins,
        PORTABLE_FEATURE_NAMES,
        ~categorical_mask,
        seed=seed,
        test_size=test_size,
    )
    blocked = full["balanced_accuracy"] >= high_accuracy_threshold
    return {
        "schema_version": "1.0.0",
        "diagnostic": "dataset_origin_classifier",
        "feature_schema": PORTABLE_SCHEMA_VERSION,
        "seed": seed,
        "split": "stratified row split after exact per-source Schema A deduplication",
        "limitations": [
            "Aggregate sources do not expose shared capture groups, so this diagnostic "
            "cannot use a capture-disjoint split.",
            "High accuracy identifies corpus separability; it does not by itself identify "
            "a causal shortcut.",
        ],
        "high_origin_accuracy_threshold": high_accuracy_threshold,
        "challenger_selection_blocked": blocked,
        "disposition": (
            "blocked_shortcut_investigation_required"
            if blocked
            else "origin_accuracy_below_blocking_threshold"
        ),
        "sources": source_summary,
        "full_schema_a": full,
        "categorical_ablation": {
            "removed_features": [
                name
                for name, removed in zip(
                    PORTABLE_FEATURE_NAMES, categorical_mask, strict=True
                )
                if removed
            ],
            **ablated,
        },
    }
