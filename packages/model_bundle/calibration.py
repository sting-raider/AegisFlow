from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np


@dataclass(frozen=True)
class EmpiricalCDF:
    """Bounded empirical CDF knots for a scalar anomaly signal."""

    values: tuple[float, ...]
    probabilities: tuple[float, ...]
    sample_count: int
    max_knots: int

    @classmethod
    def fit(cls, samples: np.ndarray, *, max_knots: int = 2_049) -> EmpiricalCDF:
        values = np.asarray(samples, dtype=np.float64).reshape(-1)
        if values.size < 2:
            raise ValueError("empirical CDF requires at least two samples")
        if max_knots < 3:
            raise ValueError("max_knots must be at least three")
        if not np.all(np.isfinite(values)):
            raise ValueError("empirical CDF samples must be finite")
        ordered = np.sort(values)
        if ordered.size <= max_knots:
            indices = np.arange(ordered.size)
        else:
            indices = np.unique(
                np.rint(np.linspace(0, ordered.size - 1, max_knots)).astype(np.int64)
            )
        sampled_values = ordered[indices]
        right_ranks = np.searchsorted(ordered, sampled_values, side="right")
        unique_values, first_indices = np.unique(sampled_values, return_index=True)
        probabilities = np.maximum.reduceat(right_ranks / ordered.size, first_indices)
        return cls(
            values=tuple(float(value) for value in unique_values),
            probabilities=tuple(float(value) for value in probabilities),
            sample_count=int(ordered.size),
            max_knots=max_knots,
        )

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> EmpiricalCDF:
        try:
            values = tuple(float(item) for item in value["values"])
            probabilities = tuple(float(item) for item in value["probabilities"])
            sample_count = int(value["sample_count"])
            max_knots = int(value["max_knots"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("invalid empirical CDF payload") from exc
        result = cls(values, probabilities, sample_count, max_knots)
        result._validate()
        return result

    def to_dict(self) -> dict[str, object]:
        self._validate()
        return {
            "values": list(self.values),
            "probabilities": list(self.probabilities),
            "sample_count": self.sample_count,
            "max_knots": self.max_knots,
        }

    def percentile(self, value: float) -> float:
        self._validate()
        if not np.isfinite(value):
            raise ValueError("anomaly score must be finite")
        if value < self.values[0]:
            return 0.0
        if value >= self.values[-1]:
            return 1.0
        return float(
            np.clip(
                np.interp(value, self.values, self.probabilities),
                0.0,
                1.0,
            )
        )

    def _validate(self) -> None:
        if self.sample_count < 2 or self.max_knots < 3:
            raise ValueError("invalid empirical CDF sample metadata")
        if not self.values or len(self.values) != len(self.probabilities):
            raise ValueError("empirical CDF knots must be non-empty and aligned")
        if len(self.values) > min(self.sample_count, self.max_knots):
            raise ValueError("empirical CDF contains more knots than its declared bounds")
        values = np.asarray(self.values, dtype=np.float64)
        probabilities = np.asarray(self.probabilities, dtype=np.float64)
        if not np.all(np.isfinite(values)) or not np.all(np.isfinite(probabilities)):
            raise ValueError("empirical CDF knots must be finite")
        if np.any(np.diff(values) <= 0) or np.any(np.diff(probabilities) < 0):
            raise ValueError("empirical CDF knots must be monotonic")
        if np.any(values < 0) or np.any(values > 1):
            raise ValueError("empirical anomaly score knots must be in [0, 1]")
        if np.any(probabilities <= 0) or np.any(probabilities > 1):
            raise ValueError("empirical CDF probabilities must be in (0, 1]")
        if abs(float(probabilities[-1]) - 1.0) > 1e-12:
            raise ValueError("empirical CDF must terminate at probability one")
