from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from typing import Any, Literal

import numpy as np
from sklearn.model_selection import GroupShuffleSplit

from training.data.models import CanonicalDataset

SplitStrategy = Literal["time", "capture_day", "source_file", "leave_family_out"]


@dataclass(frozen=True)
class DatasetSplit:
    strategy: SplitStrategy
    train_indices: np.ndarray
    test_indices: np.ndarray
    held_out_family: str | None
    train_groups: int
    test_groups: int
    group_overlap: int

    def manifest(self) -> dict[str, Any]:
        values = asdict(self)
        values["train_rows"] = len(self.train_indices)
        values["test_rows"] = len(self.test_indices)
        values["train_indices_sha256"] = hashlib.sha256(
            self.train_indices.astype("<i8", copy=False).tobytes()
        ).hexdigest()
        values["test_indices_sha256"] = hashlib.sha256(
            self.test_indices.astype("<i8", copy=False).tobytes()
        ).hexdigest()
        del values["train_indices"]
        del values["test_indices"]
        return values


def _validate_fraction(test_fraction: float) -> None:
    if not 0.05 <= test_fraction <= 0.5:
        raise ValueError("test_fraction must be between 0.05 and 0.5")


def _finish(
    dataset: CanonicalDataset,
    strategy: SplitStrategy,
    train: np.ndarray,
    test: np.ndarray,
    held_out_family: str | None = None,
) -> DatasetSplit:
    if not len(train) or not len(test):
        raise ValueError("split produced an empty train or test fold")
    if np.intersect1d(train, test).size:
        raise ValueError("split contains row overlap")
    train_groups = set(map(str, dataset.groups[train]))
    test_groups = set(map(str, dataset.groups[test]))
    return DatasetSplit(
        strategy,
        np.asarray(sorted(map(int, train)), dtype=np.int64),
        np.asarray(sorted(map(int, test)), dtype=np.int64),
        held_out_family,
        len(train_groups),
        len(test_groups),
        len(train_groups & test_groups),
    )


def create_split(
    dataset: CanonicalDataset,
    strategy: SplitStrategy,
    *,
    test_fraction: float = 0.2,
    seed: int = 431,
    held_out_family: str | None = None,
) -> DatasetSplit:
    _validate_fraction(test_fraction)
    indices = np.arange(dataset.row_count)
    if strategy == "time":
        if np.isnat(dataset.timestamps).any():
            raise ValueError("time split requires a valid timestamp for every row")
        ordered = indices[np.argsort(dataset.timestamps, kind="stable")]
        boundary = int(len(ordered) * (1 - test_fraction))
        return _finish(dataset, strategy, ordered[:boundary], ordered[boundary:])
    if strategy == "capture_day":
        if np.isnat(dataset.timestamps).any():
            raise ValueError("capture-day split requires a valid timestamp for every row")
        groups = dataset.timestamps.astype("datetime64[D]").astype(str)
    else:
        groups = dataset.groups
    if strategy in {"source_file", "capture_day"}:
        if len(set(map(str, groups))) < 2:
            raise ValueError(f"{strategy} split requires at least two groups")
        train, test = next(
            GroupShuffleSplit(n_splits=1, test_size=test_fraction, random_state=seed).split(
                indices, dataset.labels, groups
            )
        )
        return _finish(dataset, strategy, train, test)
    if strategy == "leave_family_out":
        if not held_out_family:
            raise ValueError("leave-family-out split requires held_out_family")
        held = np.flatnonzero(dataset.labels == held_out_family)
        train = np.flatnonzero(dataset.labels != held_out_family)
        if not len(held):
            raise ValueError(f"held-out family is absent: {held_out_family}")
        return _finish(dataset, strategy, train, held, held_out_family)
    raise ValueError(f"unsupported split strategy: {strategy}")


def cross_dataset_split(
    training: CanonicalDataset, testing: CanonicalDataset
) -> tuple[np.ndarray, np.ndarray]:
    if training.features.shape[1] != testing.features.shape[1]:
        raise ValueError("cross-dataset feature schemas are incompatible")
    return np.arange(training.row_count), np.arange(testing.row_count)
