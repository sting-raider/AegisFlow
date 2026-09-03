"""Leakage-controlled linear origin probes; not a network intrusion detector."""

from __future__ import annotations

import hashlib
import warnings
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from time import perf_counter
from typing import Any

import numpy as np
from sklearn.exceptions import ConvergenceWarning
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import balanced_accuracy_score, confusion_matrix, f1_score
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.preprocessing import QuantileTransformer

from training.v2.provenance import partition_provenance, sha256_file
from training.v2.registered_family import MemorySampler, quantiles
from training.v2.tensors import SequenceRecord

KINDS = ("standard", "robust", "clip_robust", "quantile_normal")


class IneligibleProbe(ValueError):
    """Declared folds cannot establish the intended out-of-group comparison."""

    def __init__(
        self,
        message: str,
        *,
        grouping: dict[str, Any] | None = None,
        splits: list[tuple[np.ndarray, np.ndarray]] | None = None,
    ) -> None:
        super().__init__(message)
        self.grouping = grouping
        self.splits = splits


def checked_matrix(matrix: np.ndarray) -> np.ndarray:
    result = np.asarray(matrix, dtype=np.float64)
    if result.ndim != 2 or not result.size or not np.isfinite(result).all():
        raise ValueError("probe features must be a finite nonempty matrix")
    return result


class NumericTransform:
    def __init__(self, kind: str, continuous: Sequence[int], *, seed: int) -> None:
        if kind not in KINDS:
            raise ValueError("unregistered numeric transformation")
        self.kind = kind
        self.continuous = list(continuous)
        self.seed = seed
        self.parameters: dict[str, np.ndarray] = {}
        self.quantile: Any = None

    def fit(self, matrix: np.ndarray) -> None:
        values = checked_matrix(matrix)
        if len(set(self.continuous)) != len(self.continuous) or any(
            i < 0 or i >= values.shape[1] for i in self.continuous
        ):
            raise ValueError("invalid continuous feature indices")
        self.parameters = {
            "continuous_indices": np.asarray(self.continuous, dtype=np.int64),
            "dimension": np.asarray([values.shape[1]], dtype=np.int64),
            "kind_code": np.asarray([KINDS.index(self.kind)], dtype=np.int64),
        }
        if not self.continuous:
            return
        numeric = values[:, self.continuous].copy()
        if self.kind == "quantile_normal":
            self.quantile = QuantileTransformer(
                n_quantiles=min(100, len(values)),
                output_distribution="normal",
                subsample=None,
                random_state=self.seed,
            )
            self.quantile.fit(numeric)
            self.parameters["quantiles"] = np.asarray(self.quantile.quantiles_)
            self.parameters["references"] = np.asarray(self.quantile.references_)
            return
        if self.kind == "clip_robust":
            low, high = np.quantile(numeric, [0.01, 0.99], axis=0)
            self.parameters.update({"clip_lower": low, "clip_upper": high})
            numeric = np.clip(numeric, low, high)
        if self.kind == "standard":
            center, scale = numeric.mean(axis=0), numeric.std(axis=0)
        else:
            low, center, high = np.quantile(numeric, [0.25, 0.5, 0.75], axis=0)
            scale = high - low
        scale[scale < 1e-9] = 1
        self.parameters.update({"center": center, "scale": scale})

    def transform(self, matrix: np.ndarray) -> np.ndarray:
        values = checked_matrix(matrix).copy()
        if not self.parameters or values.shape[1] != int(self.parameters["dimension"][0]):
            raise ValueError("numeric transform is unfitted or feature dimensions changed")
        if not self.continuous:
            return values
        numeric = values[:, self.continuous]
        if self.kind == "quantile_normal":
            values[:, self.continuous] = self.quantile.transform(numeric)
        else:
            if self.kind == "clip_robust":
                numeric = np.clip(
                    numeric, self.parameters["clip_lower"], self.parameters["clip_upper"]
                )
            values[:, self.continuous] = (numeric - self.parameters["center"]) / self.parameters[
                "scale"
            ]
        return checked_matrix(values)

    def arrays(self) -> dict[str, np.ndarray]:
        return {f"transform_{key}": value.copy() for key, value in self.parameters.items()}


def vector_keys(matrix: np.ndarray) -> list[bytes]:
    values = checked_matrix(matrix).astype("<f8", copy=True)
    values[values == 0] = 0  # Signed zero has identical estimator semantics.
    return [row.tobytes() for row in values]


def grouped_folds(
    matrix: np.ndarray, labels: np.ndarray, *, folds: int, seed: int
) -> tuple[list[tuple[np.ndarray, np.ndarray]], dict[str, Any]]:
    keys = vector_keys(matrix)
    if labels.shape != (len(matrix),) or len(np.unique(labels)) < 2:
        raise ValueError("invalid origin labels")
    mapping: dict[bytes, int] = {}
    groups = np.asarray([mapping.setdefault(key, len(mapping)) for key in keys])
    origins: dict[int, set[int]] = {}
    for group, label in zip(groups, labels, strict=True):
        origins.setdefault(int(group), set()).add(int(label))
    summary = {
        "rows": len(matrix),
        "groups": len(mapping),
        "duplicate_rows_beyond_first": len(matrix) - len(mapping),
        "cross_origin_ambiguous_groups": sum(len(values) > 1 for values in origins.values()),
        "group_assignment_sha256": hashlib.sha256(groups.astype("<i8").tobytes()).hexdigest(),
    }
    if len(mapping) < folds:
        raise IneligibleProbe(
            f"only {len(mapping)} distinct groups for {folds} folds", grouping=summary
        )
    splitter = StratifiedGroupKFold(n_splits=folds, shuffle=True, random_state=seed)
    splits = list(splitter.split(matrix, labels, groups))
    all_labels = set(labels)
    for train, test in splits:
        if set(labels[train]) != all_labels or set(labels[test]) != all_labels:
            raise IneligibleProbe(
                "grouped fold lacks an origin in training or test", grouping=summary, splits=splits
            )
        if set(groups[train]) & set(groups[test]):
            raise ValueError("origin groups overlap folds")
    return splits, summary


def reject_transformed_overlap(train: np.ndarray, test: np.ndarray) -> None:
    if set(vector_keys(train)) & set(vector_keys(test)):
        raise IneligibleProbe("transformed input aliases across train and test")


def save_probe(path: Path, model: Any, transform: NumericTransform) -> dict[str, Any]:
    arrays: dict[str, Any] = transform.arrays()
    arrays.update(
        {
            "coefficient": model.coef_,
            "intercept": model.intercept_,
            "classes": model.classes_,
            "iterations": model.n_iter_,
        }
    )
    if any(not np.isfinite(array).all() for array in arrays.values()):
        raise ValueError("nonfinite probe artifact")
    with path.open("xb") as stream:
        np.savez_compressed(stream, **arrays)
    with np.load(path, allow_pickle=False) as saved:
        if set(saved.files) != set(arrays) or any(
            not np.array_equal(array, saved[key]) for key, array in arrays.items()
        ):
            raise ValueError("probe artifact round trip failed")
    return {
        "file": path.name,
        "sha256": sha256_file(path),
        "bytes": path.stat().st_size,
        "arrays": {
            key: {"shape": list(array.shape), "dtype": str(array.dtype)}
            for key, array in arrays.items()
        },
    }


def probe_cost(
    model: Any, transform: NumericTransform, test: np.ndarray, config: dict[str, Any]
) -> list[dict[str, Any]]:
    results = []
    for size in config["measurement"]["batch_sizes"]:
        indices = np.random.default_rng(config["execution"]["seed"]).choice(
            len(test), size, replace=size > len(test)
        )
        batch = test[indices]
        for _ in range(config["measurement"]["warmups"]):
            model.predict(transform.transform(batch))
        timings = []
        for _ in range(config["measurement"]["repetitions"]):
            start = perf_counter()
            model.predict(transform.transform(batch))
            timings.append(perf_counter() - start)
        measured = np.asarray(timings)
        results.append(
            {
                "batch_size": size,
                "warmups": config["measurement"]["warmups"],
                "repetitions": len(timings),
                "scope": config["measurement"]["scope"],
                "batch_latency_ms": quantiles(measured * 1000),
                "rows_per_second": size * len(timings) / float(measured.sum()),
                "batch_features_sha256": hashlib.sha256(batch.tobytes()).hexdigest(),
            }
        )
    return results


def evaluate_view(
    name: str,
    matrix: np.ndarray,
    continuous: list[int],
    labels: np.ndarray,
    records: Sequence[SequenceRecord],
    config: dict[str, Any],
    output: Path,
) -> dict[str, Any]:
    matrix = checked_matrix(matrix)
    base: dict[str, Any] = {
        "view": name,
        "dimension": matrix.shape[1],
        "rows": len(matrix),
        "continuous_indices": continuous,
        "features_sha256": hashlib.sha256(matrix.tobytes()).hexdigest(),
    }
    try:
        splits, summary = grouped_folds(
            matrix, labels, folds=config["validation"]["folds"], seed=config["execution"]["seed"]
        )
    except IneligibleProbe as error:
        base.update({"status": "ineligible_grouped_folds", "reason": str(error), "transforms": []})
        base["grouping"] = error.grouping
        if error.splits is not None:
            base["attempted_partitions"] = [
                {
                    role: partition_provenance([records[int(i)] for i in indices])
                    for role, indices in (("train", train), ("test", test))
                }
                for train, test in error.splits
            ]
        return base
    base["grouping"] = summary
    results = []
    for kind in config["transforms"]:
        fold_results: list[dict[str, Any]] = []
        for number, (train, test) in enumerate(splits, start=1):
            fold: dict[str, Any] = {
                "fold": number,
                "partitions": {
                    "train": partition_provenance([records[int(i)] for i in train]),
                    "test": partition_provenance([records[int(i)] for i in test]),
                },
                "origin_counts": {
                    role: dict(sorted(Counter(map(int, labels[indices])).items()))
                    for role, indices in (("train", train), ("test", test))
                },
            }
            sampler = MemorySampler()
            sampler.thread.start()
            try:
                started = perf_counter()
                transform = NumericTransform(kind, continuous, seed=config["execution"]["seed"])
                transform.fit(matrix[train])
                x_train, x_test = (
                    transform.transform(matrix[train]),
                    transform.transform(matrix[test]),
                )
                reject_transformed_overlap(x_train, x_test)
                model = LogisticRegression(
                    **{k: v for k, v in config["probe"].items() if k != "class"},
                    random_state=config["execution"]["seed"],
                )
                with warnings.catch_warnings():
                    warnings.simplefilter("error", ConvergenceWarning)
                    model.fit(x_train, labels[train])
                elapsed = perf_counter() - started
                predicted = model.predict(x_test)
                confusion = confusion_matrix(labels[test], predicted, labels=np.unique(labels))
                artifact = save_probe(output / f"{name}-{kind}-fold{number}.npz", model, transform)
                fold.update(
                    {
                        "status": "evaluated",
                        "fit_seconds": elapsed,
                        "balanced_accuracy": float(
                            balanced_accuracy_score(labels[test], predicted)
                        ),
                        "macro_f1": float(f1_score(labels[test], predicted, average="macro")),
                        "confusion_matrix": confusion.tolist(),
                        "per_origin_recall": (
                            confusion.diagonal() / confusion.sum(axis=1)
                        ).tolist(),
                        "artifact": artifact,
                        "inference": probe_cost(model, transform, matrix[test], config),
                    }
                )
            except (IneligibleProbe, ConvergenceWarning) as error:
                fold.update(
                    {
                        "status": "ineligible",
                        "reason": str(error),
                        "fit_seconds": perf_counter() - started,
                    }
                )
            finally:
                fold["memory"] = sampler.finish()
            fold_results.append(fold)
        entry: dict[str, Any] = {"transform": kind, "folds": fold_results}
        if all(fold["status"] == "evaluated" for fold in fold_results):
            values = np.asarray([fold["balanced_accuracy"] for fold in fold_results])
            entry.update(
                {
                    "status": "evaluated",
                    "balanced_accuracy_mean": float(values.mean()),
                    "balanced_accuracy_std": float(values.std()),
                    "origin_warning": bool(
                        values.mean() >= config["validation"]["block_threshold"]
                    ),
                }
            )
        else:
            entry["status"] = "ineligible_incomplete_folds"
        results.append(entry)
    base.update({"status": "accounted_for", "transforms": results})
    return base
