from __future__ import annotations

from typing import Self

import numpy as np


class RobustResearchPreprocessor:
    """Training-only quantile clipping and robust scaling with binary passthrough."""

    def __init__(
        self,
        feature_names: tuple[str, ...],
        *,
        lower_quantile: float = 0.005,
        upper_quantile: float = 0.995,
    ) -> None:
        if not feature_names or len(set(feature_names)) != len(feature_names):
            raise ValueError("feature_names must be nonempty and unique")
        if not 0.0 <= lower_quantile < upper_quantile <= 1.0:
            raise ValueError("clip quantiles must be ordered within [0, 1]")
        self.feature_names = feature_names
        self.lower_quantile = lower_quantile
        self.upper_quantile = upper_quantile
        self.lower_bounds_: np.ndarray | None = None
        self.upper_bounds_: np.ndarray | None = None
        self.medians_: np.ndarray | None = None
        self.scales_: np.ndarray | None = None
        self.binary_mask_: np.ndarray | None = None

    def _validate(self, values: np.ndarray) -> np.ndarray:
        matrix = np.asarray(values, dtype=np.float64)
        if matrix.ndim != 2 or matrix.shape[1] != len(self.feature_names):
            raise ValueError("feature matrix does not match preprocessor feature order")
        if not np.isfinite(matrix).all():
            raise ValueError("research preprocessing rejects non-finite inputs")
        return matrix

    def fit(self, values: np.ndarray) -> Self:
        matrix = self._validate(values)
        if not len(matrix):
            raise ValueError("cannot fit research preprocessing on an empty matrix")
        self.lower_bounds_ = np.quantile(matrix, self.lower_quantile, axis=0)
        self.upper_bounds_ = np.quantile(matrix, self.upper_quantile, axis=0)
        self.medians_ = np.median(matrix, axis=0)
        declared_binary = np.asarray(
            [
                name.startswith(("protocol_", "port_", "service_"))
                or name.endswith(
                    ("_missing", "_novelty_60s", "_cold_start", "_late_event")
                )
                for name in self.feature_names
            ]
        )
        self.binary_mask_ = declared_binary & np.all(
            (matrix == 0.0) | (matrix == 1.0), axis=0
        )
        lower_quartile = np.quantile(matrix, 0.25, axis=0)
        upper_quartile = np.quantile(matrix, 0.75, axis=0)
        scales = upper_quartile - lower_quartile
        scales[scales < 1e-9] = 1.0
        scales[self.binary_mask_] = 1.0
        self.scales_ = scales
        return self

    def transform(self, values: np.ndarray) -> np.ndarray:
        matrix = self._validate(values)
        learned = (
            self.lower_bounds_,
            self.upper_bounds_,
            self.medians_,
            self.scales_,
            self.binary_mask_,
        )
        if any(item is None for item in learned):
            raise ValueError("research preprocessor must be fitted before transform")
        lower, upper, medians, scales, binary = learned
        assert lower is not None and upper is not None
        assert medians is not None and scales is not None and binary is not None
        clipped = np.clip(matrix, lower, upper)
        transformed = (clipped - medians) / scales
        transformed[:, binary] = clipped[:, binary]
        return np.asarray(transformed, dtype=np.float64)

    def fit_transform(self, values: np.ndarray) -> np.ndarray:
        return self.fit(values).transform(values)

    def manifest(self) -> dict[str, object]:
        if self.lower_bounds_ is None or self.upper_bounds_ is None:
            raise ValueError("research preprocessor must be fitted before manifest")
        assert self.medians_ is not None and self.scales_ is not None
        assert self.binary_mask_ is not None
        return {
            "type": "training_quantile_clip_and_robust_scale",
            "feature_order": list(self.feature_names),
            "lower_quantile": self.lower_quantile,
            "upper_quantile": self.upper_quantile,
            "lower_bounds": self.lower_bounds_.tolist(),
            "upper_bounds": self.upper_bounds_.tolist(),
            "medians": self.medians_.tolist(),
            "scales": self.scales_.tolist(),
            "binary_passthrough": [
                name
                for name, binary in zip(
                    self.feature_names, self.binary_mask_.tolist(), strict=True
                )
                if binary
            ],
        }
