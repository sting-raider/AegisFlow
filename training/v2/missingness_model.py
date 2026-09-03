"""Numeric-only linear/raw-distance models for the registered missingness study."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from time import perf_counter
from typing import Any

import numpy as np
from sklearn.linear_model import LogisticRegression

from training.v2.missingness import MissingnessTransform, ObservedInputs, observation_inputs
from training.v2.provenance import canonical_digest, sha256_file
from training.v2.registered_family import quantiles
from training.v2.run_held_family import mahalanobis_distances
from training.v2.tensors import SequenceRecord

MODEL_ARRAYS = {"coefficient", "intercept", "classes", "iterations", "ood_center", "ood_inverse"}


class MissingnessPredictor:
    def __init__(
        self,
        transform: MissingnessTransform,
        model: Any,
        ood_center: np.ndarray,
        ood_inverse: np.ndarray,
    ) -> None:
        self.transform, self.model = transform, model
        self.ood_center, self.ood_inverse = ood_center, ood_inverse

    def score_inputs(self, inputs: ObservedInputs) -> tuple[np.ndarray, np.ndarray]:
        matrix = self.transform.transform(inputs)
        scores = np.asarray(self.model.predict_proba(matrix)[:, 1], dtype=np.float64)
        with np.errstate(invalid="raise", over="raise"):
            distances = mahalanobis_distances(matrix, self.ood_center, self.ood_inverse)
        if (
            not np.isfinite(scores).all()
            or not np.isfinite(distances).all()
            or not ((scores >= 0) & (scores <= 1)).all()
            or (distances < 0).any()
        ):
            raise FloatingPointError("invalid fitted model probability or distance")
        return scores, distances

    def score(self, records: Sequence[SequenceRecord]) -> tuple[np.ndarray, np.ndarray]:
        return self.score_inputs(observation_inputs(records))

    def save(self, path: Path) -> dict[str, Any]:
        arrays: dict[str, Any] = {
            **self.transform.arrays(),
            "coefficient": np.asarray(self.model.coef_, dtype=np.float64),
            "intercept": np.asarray(self.model.intercept_, dtype=np.float64),
            "classes": np.asarray(self.model.classes_, dtype=np.int64),
            "iterations": np.asarray(self.model.n_iter_, dtype=np.int64),
            "ood_center": self.ood_center,
            "ood_inverse": self.ood_inverse,
        }
        if any(not np.isfinite(value).all() for value in arrays.values()):
            raise ValueError("nonfinite model parameters cannot become an artifact")
        with path.open("xb") as stream:
            np.savez_compressed(stream, **arrays)
        with np.load(path, allow_pickle=False) as saved:
            if set(saved.files) != set(arrays) or any(
                not np.array_equal(saved[key], value) for key, value in arrays.items()
            ):
                raise ValueError("numeric model artifact round trip failed")
        return {
            "file": path.name,
            "sha256": sha256_file(path),
            "bytes": path.stat().st_size,
            "format": "numpy_numeric_arrays_no_pickle",
            "arrays": {
                key: {"shape": list(value.shape), "dtype": str(value.dtype)}
                for key, value in arrays.items()
            },
        }


def load_predictor(
    path: Path,
    metadata: Mapping[str, Any],
    config: Mapping[str, Any],
) -> MissingnessPredictor:
    if (
        path.name != metadata["file"]
        or sha256_file(path) != metadata["sha256"]
        or path.stat().st_size != metadata["bytes"]
    ):
        raise ValueError("missingness model artifact hash/size mismatch")
    with np.load(path, allow_pickle=False) as saved:
        arrays = {key: np.array(saved[key], copy=True) for key in saved.files}
    if set(arrays) != set(metadata["arrays"]) or not MODEL_ARRAYS <= arrays.keys():
        raise ValueError("missingness model artifact keys mismatch")
    for key, value in arrays.items():
        declared = metadata["arrays"][key]
        if (
            value.dtype.kind not in "fiu"
            or not np.isfinite(value).all()
            or list(value.shape) != declared["shape"]
            or str(value.dtype) != declared["dtype"]
        ):
            raise ValueError("missingness model artifact shape/dtype mismatch")
    transform = MissingnessTransform.from_arrays(
        {key: value for key, value in arrays.items() if key not in MODEL_ARRAYS}
    )
    width = len(transform.feature_names)
    shapes = {
        "coefficient": (1, width),
        "intercept": (1,),
        "classes": (2,),
        "iterations": (1,),
        "ood_center": (width,),
        "ood_inverse": (width, width),
    }
    if (
        any(arrays[key].shape != shape for key, shape in shapes.items())
        or not np.array_equal(arrays["classes"], [0, 1])
        or arrays["iterations"].dtype.kind not in "iu"
        or not 1 <= int(arrays["iterations"][0]) <= config["model"]["max_iter"]
        or transform.seed != config["execution"]["seed"]
    ):
        raise ValueError("missingness model parameters violate registered dimensions/classes")
    model = LogisticRegression(**model_kwargs(config))
    model.coef_, model.intercept_ = arrays["coefficient"], arrays["intercept"]
    model.classes_, model.n_iter_, model.n_features_in_ = (
        arrays["classes"],
        arrays["iterations"],
        width,
    )
    return MissingnessPredictor(transform, model, arrays["ood_center"], arrays["ood_inverse"])


def model_kwargs(config: Mapping[str, Any]) -> dict[str, Any]:
    return {
        **{
            key: config["model"][key]
            for key in (
                "C",
                "solver",
                "tol",
                "max_iter",
                "fit_intercept",
                "class_weight",
            )
        },
        "random_state": config["execution"]["seed"],
    }


def benchmark(
    predictor: MissingnessPredictor,
    records: Sequence[SequenceRecord],
    config: Mapping[str, Any],
) -> list[dict[str, Any]]:
    results = []
    measurement = config["measurement"]
    for size in measurement["batch_sizes"]:
        indices = np.random.default_rng(config["execution"]["seed"]).choice(
            len(records), size, replace=size > len(records)
        )
        batch = [records[int(i)] for i in indices]
        for _ in range(measurement["warmup_calls_per_batch_size"]):
            predictor.score(batch)
        timings = []
        for _ in range(measurement["measured_calls_per_batch_size"]):
            started = perf_counter()
            predictor.score(batch)
            timings.append(perf_counter() - started)
        measured = np.asarray(timings)
        results.append(
            {
                "batch_size": size,
                "warmup_calls": measurement["warmup_calls_per_batch_size"],
                "measured_calls": len(timings),
                "scope": measurement["inference_scope"],
                "batch_record_content_sha256": canonical_digest(batch),
                "batch_family_counts": dict(Counter(r["family"] for r in batch)),
                "batch_latency_ms": quantiles(measured * 1000),
                "throughput_flows_per_second": size * len(timings) / float(measured.sum()),
                "not_durable_pipeline_throughput": True,
            }
        )
    return results
