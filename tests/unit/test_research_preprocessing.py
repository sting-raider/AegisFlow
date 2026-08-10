from __future__ import annotations

import numpy as np
import pytest

from training.features import RobustResearchPreprocessor


def test_preprocessor_clips_from_training_only_and_preserves_binary_geometry() -> None:
    training = np.asarray(
        [[0.0, 0.0], [1.0, 10.0], [0.0, 20.0], [1.0, 30.0]], dtype=np.float64
    )
    processor = RobustResearchPreprocessor(
        ("protocol_tcp", "bytes_total_log1p"), lower_quantile=0.0, upper_quantile=0.75
    ).fit(training)
    learned_upper = processor.upper_bounds_.copy()  # type: ignore[union-attr]

    transformed = processor.transform(np.asarray([[1.0, 1_000_000.0]]))

    np.testing.assert_array_equal(processor.upper_bounds_, learned_upper)
    assert transformed[0, 0] == 1.0
    assert transformed[0, 1] == pytest.approx(0.5)
    assert processor.manifest()["binary_passthrough"] == ["protocol_tcp"]


def test_preprocessor_fails_closed_on_shape_nonfinite_and_unfitted_use() -> None:
    processor = RobustResearchPreprocessor(("one", "two"))
    with pytest.raises(ValueError, match="fitted"):
        processor.transform(np.ones((1, 2)))
    with pytest.raises(ValueError, match="feature order"):
        processor.fit(np.ones((1, 3)))
    with pytest.raises(ValueError, match="non-finite"):
        processor.fit(np.asarray([[1.0, np.nan]]))
