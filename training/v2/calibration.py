"""Empirical benign-budget cut points with exact >= decision semantics."""

from __future__ import annotations

import math

import numpy as np


def threshold_for_fpr(benign_scores: np.ndarray, budget: float) -> float:
    """Meet the calibration budget without splitting tied groups or rounding cuts.

    This controls the supplied benign reference only. Independent benign FPR must
    still be measured, and budgets across multiple OR-combined channels must sum
    to the desired total budget.
    """
    scores = np.asarray(benign_scores, dtype=np.float64)
    if scores.ndim != 1 or not scores.size or not np.isfinite(scores).all():
        raise ValueError("calibration scores must be finite, one-dimensional and nonempty")
    if not math.isfinite(budget) or not 0 <= budget <= 1:
        raise ValueError("calibration FPR budget must be in [0, 1]")
    allowed = math.floor(budget * len(scores) + 1e-12)
    ordered = np.sort(scores)[::-1]
    if allowed == len(scores):
        return float(ordered[-1])
    with np.errstate(over="ignore"):
        threshold = float(np.nextafter(ordered[allowed], np.inf))
    if not math.isfinite(threshold):
        raise ValueError("cannot represent a finite cut above the calibration boundary")
    if int((scores >= threshold).sum()) > allowed:
        raise ValueError("calibration budget could not be satisfied")
    return threshold
