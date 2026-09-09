"""Transparent numeric model used by the registered context ablation."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.linear_model import LogisticRegression

from training.v2.missingness_model import model_kwargs
from training.v2.provenance import sha256_file
from training.v2.registered_context import VIEWS
from training.v2.run_held_family import mahalanobis_distances

MODEL_ARRAYS = {
    "mean",
    "scale",
    "coefficient",
    "intercept",
    "classes",
    "iterations",
    "ood_center",
    "ood_inverse",
    "view_sha256",
}


def _matrix(value: np.ndarray, *, width: int | None = None) -> np.ndarray:
    matrix = np.asarray(value, dtype=np.float64)
    if (
        matrix.ndim != 2
        or matrix.shape[0] < 1
        or (width is not None and matrix.shape[1] != width)
        or not np.isfinite(matrix).all()
    ):
        raise ValueError("context model requires a finite nonempty 2D matrix")
    return matrix


@dataclass(frozen=True)
class StandardTransform:
    mean: np.ndarray
    scale: np.ndarray

    @classmethod
    def fit(cls, values: np.ndarray, *, scale_floor: float) -> StandardTransform:
        matrix = _matrix(values)
        if not np.isfinite(scale_floor) or scale_floor <= 0:
            raise ValueError("standardization scale floor must be positive and finite")
        mean = matrix.mean(axis=0)
        scale = np.maximum(matrix.std(axis=0), scale_floor)
        return cls(mean=np.asarray(mean), scale=np.asarray(scale))

    def transform(self, values: np.ndarray) -> np.ndarray:
        matrix = _matrix(values, width=len(self.mean))
        transformed = (matrix - self.mean) / self.scale
        if not np.isfinite(transformed).all():
            raise FloatingPointError("standardized context input is nonfinite")
        return np.asarray(transformed, dtype=np.float64)


class ContextPredictor:
    def __init__(
        self,
        transform: StandardTransform,
        model: Any,
        ood_center: np.ndarray,
        ood_inverse: np.ndarray,
    ) -> None:
        self.transform = transform
        self.model = model
        self.ood_center = np.asarray(ood_center, dtype=np.float64)
        self.ood_inverse = np.asarray(ood_inverse, dtype=np.float64)

    def score_matrix(self, values: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        matrix = self.transform.transform(values)
        scores = np.asarray(self.model.predict_proba(matrix)[:, 1], dtype=np.float64)
        with np.errstate(invalid="raise", over="raise"):
            distances = mahalanobis_distances(
                matrix, self.ood_center, self.ood_inverse
            )
        if (
            not np.isfinite(scores).all()
            or not np.isfinite(distances).all()
            or not ((scores >= 0) & (scores <= 1)).all()
            or (distances < 0).any()
        ):
            raise FloatingPointError("invalid context-model probability or distance")
        return scores, distances

    def save(self, path: Path, *, view: str) -> dict[str, Any]:
        if view not in VIEWS:
            raise ValueError("unknown registered context view")
        arrays: dict[str, Any] = {
            "mean": self.transform.mean,
            "scale": self.transform.scale,
            "coefficient": np.asarray(self.model.coef_, dtype=np.float64),
            "intercept": np.asarray(self.model.intercept_, dtype=np.float64),
            "classes": np.asarray(self.model.classes_, dtype=np.int64),
            "iterations": np.asarray(self.model.n_iter_, dtype=np.int64),
            "ood_center": self.ood_center,
            "ood_inverse": self.ood_inverse,
            "view_sha256": np.frombuffer(
                hashlib.sha256(view.encode()).digest(), dtype=np.uint8
            ).copy(),
        }
        if set(arrays) != MODEL_ARRAYS or any(
            not np.isfinite(value).all() for value in arrays.values()
        ):
            raise ValueError("invalid context model arrays cannot become an artifact")
        with path.open("xb") as stream:
            np.savez_compressed(stream, **arrays)
        with np.load(path, allow_pickle=False) as saved:
            if set(saved.files) != MODEL_ARRAYS or any(
                not np.array_equal(saved[key], value) for key, value in arrays.items()
            ):
                raise ValueError("context model artifact round trip failed")
        return {
            "file": path.name,
            "sha256": sha256_file(path),
            "bytes": path.stat().st_size,
            "format": "numpy_numeric_arrays_no_pickle",
            "view": view,
            "arrays": {
                key: {"shape": list(value.shape), "dtype": str(value.dtype)}
                for key, value in arrays.items()
            },
        }


def fit_context_predictor(
    values: np.ndarray,
    labels: np.ndarray,
    config: Mapping[str, Any],
) -> ContextPredictor:
    matrix = _matrix(values, width=config["representation"]["dimension"])
    targets = np.asarray(labels, dtype=np.int64)
    if targets.shape != (len(matrix),) or set(targets.tolist()) != {0, 1}:
        raise ValueError("context model fit requires aligned binary classes")
    transform = StandardTransform.fit(
        matrix, scale_floor=config["representation"]["scale_floor"]
    )
    transformed = transform.transform(matrix)
    model = LogisticRegression(**model_kwargs(config))
    model.fit(transformed, targets)
    benign = transformed[targets == 0]
    if len(benign) < 2:
        raise ValueError("context benign covariance requires at least two rows")
    center = benign.mean(axis=0)
    covariance = np.cov(benign, rowvar=False)
    covariance += np.eye(covariance.shape[0]) * config["ood"]["covariance_ridge"]
    inverse = np.linalg.inv(covariance)
    if not np.isfinite(inverse).all():
        raise FloatingPointError("context covariance inverse is nonfinite")
    return ContextPredictor(transform, model, center, inverse)


def load_context_predictor(
    path: Path,
    metadata: Mapping[str, Any],
    config: Mapping[str, Any],
    *,
    view: str,
) -> ContextPredictor:
    if (
        path.name != metadata["file"]
        or path.stat().st_size != metadata["bytes"]
        or sha256_file(path) != metadata["sha256"]
    ):
        raise ValueError("context model artifact hash/size mismatch")
    with np.load(path, allow_pickle=False) as saved:
        arrays = {key: np.array(saved[key], copy=True) for key in saved.files}
    width = config["representation"]["dimension"]
    shapes = {
        "mean": (width,),
        "scale": (width,),
        "coefficient": (1, width),
        "intercept": (1,),
        "classes": (2,),
        "iterations": (1,),
        "ood_center": (width,),
        "ood_inverse": (width, width),
        "view_sha256": (32,),
    }
    if (
        set(arrays) != MODEL_ARRAYS
        or any(
            arrays[key].shape != shape or not np.isfinite(arrays[key]).all()
            for key, shape in shapes.items()
        )
        or not np.array_equal(arrays["classes"], [0, 1])
        or arrays["iterations"].dtype.kind not in "iu"
        or arrays["view_sha256"].dtype != np.uint8
        or not np.array_equal(
            arrays["view_sha256"],
            np.frombuffer(hashlib.sha256(view.encode()).digest(), dtype=np.uint8),
        )
        or metadata.get("view") != view
        or not 1 <= int(arrays["iterations"][0]) <= config["model"]["max_iter"]
        or (arrays["scale"] <= 0).any()
    ):
        raise ValueError("context model artifact violates registered dimensions")
    declared = metadata["arrays"]
    if set(declared) != MODEL_ARRAYS or any(
        list(arrays[key].shape) != declared[key]["shape"]
        or str(arrays[key].dtype) != declared[key]["dtype"]
        for key in arrays
    ):
        raise ValueError("context model artifact metadata mismatch")
    model = LogisticRegression(**model_kwargs(config))
    model.coef_, model.intercept_ = arrays["coefficient"], arrays["intercept"]
    model.classes_, model.n_iter_, model.n_features_in_ = (
        arrays["classes"],
        arrays["iterations"],
        width,
    )
    return ContextPredictor(
        StandardTransform(arrays["mean"], arrays["scale"]),
        model,
        arrays["ood_center"],
        arrays["ood_inverse"],
    )
