from __future__ import annotations

import numpy as np
import pytest

from packages.model_bundle.calibration import EmpiricalCDF


def test_empirical_cdf_uses_right_rank_and_interpolates_between_knots() -> None:
    calibration = EmpiricalCDF.fit(np.asarray([0.1, 0.1, 0.3, 0.7]))

    assert calibration.percentile(0.0) == 0.0
    assert calibration.percentile(0.1) == 0.5
    assert calibration.percentile(0.2) == pytest.approx(0.625)
    assert calibration.percentile(0.3) == 0.75
    assert calibration.percentile(0.7) == 1.0
    assert EmpiricalCDF.from_dict(calibration.to_dict()) == calibration


def test_empirical_cdf_is_bounded_and_rejects_invalid_samples() -> None:
    samples = np.linspace(0.0, 1.0, 10_000)
    calibration = EmpiricalCDF.fit(samples, max_knots=101)
    assert len(calibration.values) <= 101
    assert calibration.sample_count == 10_000
    assert calibration.percentile(0.5) == pytest.approx(0.5, abs=0.02)
    with pytest.raises(ValueError, match="at least two"):
        EmpiricalCDF.fit(np.asarray([0.1]))
    with pytest.raises(ValueError, match="finite"):
        EmpiricalCDF.fit(np.asarray([0.1, np.inf]))
