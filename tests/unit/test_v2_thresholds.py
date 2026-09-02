from __future__ import annotations

import numpy as np
import pytest

from training.v2.calibration import threshold_for_fpr
from training.v2.run_site_calibration import site_recall_curve


def test_site_curve_ties_cannot_turn_one_percent_budget_into_all_benign_alerts() -> None:
    scores = np.full(200, 0.5)
    curve = site_recall_curve(
        np.asarray([0.5, 0.9]), np.asarray([0.0, 1.0]), ["benign", "c_and_c"], scores,
    )
    point = curve["site_p990"]
    assert isinstance(point, dict)
    assert float(point["threshold"]) > 0.5
    assert (scores >= float(point["threshold"])).mean() <= 0.01
    assert point["calibration_fpr"] == 0.0


@pytest.mark.parametrize("budget", [0.0, 0.005, 0.01, 0.025, 0.5, 1.0])
def test_tie_aware_threshold_obeys_empirical_budget(budget: float) -> None:
    scores = np.repeat(np.linspace(0.0, 1.0, 10), 17)
    threshold = threshold_for_fpr(scores, budget)
    assert float((scores >= threshold).mean()) <= budget + 1e-12


def test_or_combined_channels_obey_the_sum_of_their_calibration_budgets() -> None:
    first = np.arange(1000, dtype=float)
    second = first[::-1]
    left = first >= threshold_for_fpr(first, 0.005)
    right = second >= threshold_for_fpr(second, 0.005)
    assert (left | right).mean() <= 0.01


@pytest.mark.parametrize("scores", [[], [np.nan], [np.inf], [[0.5]]])
def test_invalid_calibration_reference_is_rejected(scores: list[object]) -> None:
    with pytest.raises(ValueError, match="calibration scores"):
        threshold_for_fpr(np.asarray(scores), 0.01)


@pytest.mark.parametrize("budget", [-0.1, 1.1, float("nan")])
def test_invalid_calibration_budget_is_rejected(budget: float) -> None:
    with pytest.raises(ValueError, match="FPR budget"):
        threshold_for_fpr(np.asarray([0.5]), budget)


def test_threshold_is_not_rounded_back_onto_excluded_ties() -> None:
    threshold = threshold_for_fpr(np.full(100, 0.123456), 0.01)
    assert threshold > 0.123456
    assert threshold < 0.123457
