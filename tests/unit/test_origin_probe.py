from __future__ import annotations

import numpy as np
import pytest

from training.v2.origin_probe import NumericTransform, grouped_folds, reject_transformed_overlap


@pytest.mark.parametrize("kind", ["standard", "robust", "clip_robust", "quantile_normal"])
def test_numeric_transform_is_fit_only_and_preserves_categorical_geometry(kind: str) -> None:
    train = np.array([[0.0, 0.0, 1.0], [2.0, 1.0, 0.0], [4.0, 1.0, 1.0], [6.0, 0.0, 0.0]])
    transform = NumericTransform(kind, [0], seed=20260902)
    transform.fit(train)
    before = {key: value.copy() for key, value in transform.arrays().items()}
    result = transform.transform(np.array([[100.0, 1.0, 0.0], [-100.0, 0.0, 1.0]]))
    assert np.array_equal(result[:, 1:], [[1.0, 0.0], [0.0, 1.0]])
    assert all(np.array_equal(before[key], value) for key, value in transform.arrays().items())
    assert np.isfinite(result).all()


def test_grouped_probe_never_splits_identical_vectors() -> None:
    # Every group has all origins, guaranteeing a valid positive fixture; a
    # separate real-data gate still rejects any stratifier output missing one.
    matrix = np.repeat(np.arange(60, dtype=float), 6).reshape(-1, 1)
    labels = np.tile([0, 0, 1, 1, 2, 2], 60)
    splits, summary = grouped_folds(matrix, labels, folds=5, seed=20260902)
    assert len(splits) == 5
    assert summary["groups"] == 60
    for train, test in splits:
        assert not set(matrix[train, 0]) & set(matrix[test, 0])
        assert set(labels[train]) == set(labels[test]) == {0, 1, 2}


def test_grouped_probe_rejects_a_fold_missing_an_origin() -> None:
    matrix = np.repeat(np.arange(60, dtype=float), 2).reshape(-1, 1)
    labels = np.repeat(np.arange(60) % 3, 2)
    with pytest.raises(ValueError, match="lacks an origin"):
        grouped_folds(matrix, labels, folds=5, seed=20260902)


def test_constant_origin_view_is_not_given_fabricated_cv_accuracy() -> None:
    with pytest.raises(ValueError, match="groups"):
        grouped_folds(np.ones((30, 4)), np.tile([0, 1, 2], 10), folds=5, seed=1)


def test_transformation_introduced_aliasing_fails_closed() -> None:
    with pytest.raises(ValueError, match="transformed"):
        reject_transformed_overlap(np.array([[0.0, 1.0]]), np.array([[0.0, 1.0]]))


@pytest.mark.parametrize("bad", [np.nan, np.inf])
def test_nonfinite_probe_features_are_errors(bad: float) -> None:
    with pytest.raises(ValueError, match="finite"):
        NumericTransform("standard", [0], seed=1).fit(np.array([[1.0], [bad]]))
