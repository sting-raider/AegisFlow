from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest

from training.v2.context_model import (
    StandardTransform,
    fit_context_predictor,
    load_context_predictor,
)
from training.v2.registered_context import load_registration


def _config() -> dict:
    return load_registration(Path(__file__).resolve().parents[2])


def _data() -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(20260910)
    benign = rng.normal(0, 0.5, size=(30, 25))
    attack = rng.normal(1, 0.5, size=(30, 25))
    return np.vstack((benign, attack)), np.asarray([0] * 30 + [1] * 30)


def test_standard_transform_uses_fit_statistics_and_scale_floor() -> None:
    values = np.asarray([[1.0, 2.0], [1.0, 4.0], [1.0, 6.0]])
    transform = StandardTransform.fit(values, scale_floor=1e-9)

    np.testing.assert_array_equal(transform.mean, [1.0, 4.0])
    assert transform.scale[0] == 1e-9
    np.testing.assert_allclose(transform.transform(values).mean(axis=0), 0.0, atol=1e-12)
    assert transform.transform(np.asarray([[1.0, 8.0]])).shape == (1, 2)


def test_context_predictor_round_trip_preserves_exact_scores(tmp_path: Path) -> None:
    values, labels = _data()
    config = _config()
    predictor = fit_context_predictor(values, labels, config)
    before = predictor.score_matrix(values)
    path = tmp_path / "context-model.npz"

    metadata = predictor.save(path, view="causal_context")
    restored = load_context_predictor(
        path, metadata, config, view="causal_context"
    )
    after = restored.score_matrix(values)

    for left, right in zip(before, after, strict=True):
        np.testing.assert_array_equal(left, right)
    assert metadata["format"] == "numpy_numeric_arrays_no_pickle"


def test_context_model_rejects_invalid_fit_and_artifact_mutation(tmp_path: Path) -> None:
    values, labels = _data()
    config = _config()
    with pytest.raises(ValueError, match="binary classes"):
        fit_context_predictor(values, np.zeros(len(values)), config)
    invalid = values.copy()
    invalid[0, 0] = np.inf
    with pytest.raises(ValueError, match="finite nonempty"):
        fit_context_predictor(invalid, labels, config)

    predictor = fit_context_predictor(values, labels, config)
    path = tmp_path / "context-model.npz"
    metadata = predictor.save(path, view="causal_context")
    mutated = dict(metadata)
    mutated["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="hash/size mismatch"):
        load_context_predictor(path, mutated, config, view="causal_context")

    with pytest.raises(ValueError, match="registered dimensions"):
        load_context_predictor(path, metadata, config, view="shuffled_context")
