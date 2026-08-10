from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np

from packages.features.registry import FEATURE_NAMES
from packages.features.research import PORTABLE_FEATURE_NAMES, RUNTIME_ENRICHED_FEATURE_NAMES


@dataclass(frozen=True)
class SourceColumnProfile:
    name: str
    unique_count: int
    unique_ratio: float
    label_purity: float
    identifier_like: bool


@dataclass(frozen=True)
class InputProvenance:
    filename: str
    size_bytes: int
    sha256: str
    declared_manifest: dict[str, Any] | None


@dataclass(frozen=True)
class RowExclusion:
    reason: str
    count: int


@dataclass(frozen=True)
class CanonicalDataset:
    name: str
    features: np.ndarray
    labels: np.ndarray
    raw_labels: np.ndarray
    groups: np.ndarray
    timestamps: np.ndarray
    source_files: np.ndarray
    raw_column_names: tuple[str, ...]
    source_profiles: tuple[SourceColumnProfile, ...]
    provenance: tuple[InputProvenance, ...]
    adapter_notes: tuple[str, ...] = ()
    row_exclusions: tuple[RowExclusion, ...] = ()
    portable_features: np.ndarray | None = None
    runtime_enriched_features: np.ndarray | None = None
    research_feature_notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        rows = len(self.labels)
        if self.features.shape != (rows, len(FEATURE_NAMES)):
            raise ValueError("dataset feature matrix does not match the canonical schema")
        for values in (self.raw_labels, self.groups, self.timestamps, self.source_files):
            if len(values) != rows:
                raise ValueError("dataset metadata length does not match feature rows")
        if self.portable_features is not None and self.portable_features.shape != (
            rows,
            len(PORTABLE_FEATURE_NAMES),
        ):
            raise ValueError("portable feature matrix does not match research schema A")
        if self.runtime_enriched_features is not None and self.runtime_enriched_features.shape != (
            rows,
            len(RUNTIME_ENRICHED_FEATURE_NAMES),
        ):
            raise ValueError("runtime-enriched feature matrix does not match research schema B")

    @property
    def row_count(self) -> int:
        return len(self.labels)

    @property
    def fingerprint(self) -> str:
        import hashlib

        digest = hashlib.sha256()
        for provenance in self.provenance:
            digest.update(provenance.sha256.encode("ascii"))
        digest.update(self.name.encode("utf-8"))
        digest.update(str(self.row_count).encode("ascii"))
        for exclusion in self.row_exclusions:
            digest.update(exclusion.reason.encode("utf-8"))
            digest.update(str(exclusion.count).encode("ascii"))
        return digest.hexdigest()
