"""Training-only packet-availability ablations over the shared sequence contract.

An unobserved slot is not a malformed numeric value and does not imply packet loss.
These transforms are research components, not authorization to change a live model.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Self

import numpy as np
from sklearn.preprocessing import QuantileTransformer

from packages.detection_v2.sequences import SEQUENCE_MAX_LENGTH, sequence_arrays
from packages.features.research import PORTABLE_NUMERICAL_CORE_FEATURE_NAMES
from training.v2.origin_probe import KINDS, NumericTransform
from training.v2.tensors import SequenceRecord, aggregate_matrix

VIEWS = ("portable_intersection", "imputation_only", "imputation_missingness")
CHANNELS = ("signed_log1p_size", "log1p_iat_ms", "reverse_direction")
CORE_DIM = len(PORTABLE_NUMERICAL_CORE_FEATURE_NAMES)
INPUT_NAMES = PORTABLE_NUMERICAL_CORE_FEATURE_NAMES + tuple(
    f"packet_{slot + 1}_{channel}" for slot in range(SEQUENCE_MAX_LENGTH) for channel in CHANNELS
)
INDICATOR_NAMES = tuple(f"packet_{slot + 1}_unobserved" for slot in range(SEQUENCE_MAX_LENGTH))
DIRECTION_INDICES = tuple(CORE_DIM + slot * 3 + 2 for slot in range(SEQUENCE_MAX_LENGTH))


@dataclass(frozen=True)
class ObservedInputs:
    values: np.ndarray
    observed: np.ndarray

    def checked(self) -> ObservedInputs:
        if (
            self.values.ndim != 2
            or not len(self.values)
            or self.values.shape[1] != len(INPUT_NAMES)
            or self.observed.shape != self.values.shape
            or self.observed.dtype != np.dtype(bool)
            or self.values.dtype.kind not in "fiu"
            or not np.isfinite(self.values).all()
        ):
            raise ValueError("missingness inputs require finite aligned values and boolean masks")
        if not self.observed[:, :CORE_DIM].all():
            raise ValueError("portable-intersection features must all be observed")
        masks = self.observed[:, CORE_DIM:].reshape(-1, SEQUENCE_MAX_LENGTH, 3)
        if not (masks == masks[:, :, :1]).all():
            raise ValueError("packet availability must agree across its three channels")
        if np.any(np.diff(masks[:, :, 0].astype(int), axis=1) > 0):
            raise ValueError("packet observations must form a prefix")
        if (self.values[~self.observed] != 0).any():
            raise ValueError("unobserved slots must use canonical zero placeholders")
        if not np.isin(self.values[:, DIRECTION_INDICES], [0, 1]).all():
            raise ValueError("packet direction indicators must be binary")
        return self

    def subset(self, indices: np.ndarray) -> ObservedInputs:
        return ObservedInputs(self.values[indices], self.observed[indices]).checked()

    def support(self) -> dict[str, Any]:
        self.checked()
        return {
            "rows": len(self.values),
            "observed_counts_by_feature": self.observed.sum(axis=0).tolist(),
            "rows_without_observed_packets": int((~self.observed[:, CORE_DIM]).sum()),
            "fully_observed_rows": int(self.observed.all(axis=1).sum()),
            "unobserved_meaning": "no_complete_packet_metadata_for_slot_not_inferred_packet_loss",
        }


def observation_inputs(records: Sequence[SequenceRecord]) -> ObservedInputs:
    """No labels, source IDs, port categories or sequence-position channel are inputs."""
    if not records:
        raise ValueError("cannot construct missingness inputs from no records")
    values = np.zeros((len(records), len(INPUT_NAMES)), dtype=np.float64)
    observed = np.ones(values.shape, dtype=bool)
    values[:, :CORE_DIM] = aggregate_matrix(records)[:, :CORE_DIM]
    for index, record in enumerate(records):
        tensor, mask = sequence_arrays(
            record["seq_sizes"], record["seq_directions"], record["seq_iats_ms"]
        )
        values[index, CORE_DIM:] = tensor[:, :3].reshape(-1)
        observed[index, CORE_DIM:] = np.repeat(mask.astype(bool), 3)
    return ObservedInputs(values, observed).checked()


class MissingnessTransform:
    """Median/mode imputation, then numeric scaling; explicit fixed-schema indicators.

    Only observed fitting values determine replacements. Empty fitting columns receive
    a declared zero fallback, never a value learned from calibration or test data.
    Numeric scaling is fitted after imputation, with direction bits passed through.
    """

    def __init__(self, view: str, kind: str, *, seed: int) -> None:
        if view not in VIEWS or kind not in KINDS:
            raise ValueError("unregistered missingness view or numeric transform")
        if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed < 2**32:
            raise ValueError("missingness seed must be an unsigned 32-bit integer")
        self.view, self.kind, self.seed = view, kind, seed
        self.fill: np.ndarray | None = None
        self.observed_counts: np.ndarray | None = None
        self.numeric: NumericTransform | None = None

    @property
    def width(self) -> int:
        return CORE_DIM if self.view == "portable_intersection" else len(INPUT_NAMES)

    @property
    def feature_names(self) -> tuple[str, ...]:
        names = INPUT_NAMES[: self.width]
        return names + INDICATOR_NAMES if self.view == "imputation_missingness" else names

    @property
    def continuous(self) -> list[int]:
        return [i for i in range(self.width) if i not in DIRECTION_INDICES]

    def fit(self, inputs: ObservedInputs) -> Self:
        inputs.checked()
        values, observed = inputs.values[:, : self.width], inputs.observed[:, : self.width]
        counts = observed.sum(axis=0)
        fill = np.zeros(self.width, dtype=np.float64)
        for column in range(self.width):
            available = values[observed[:, column], column]
            if not len(available):
                continue
            if column in DIRECTION_INDICES:
                fill[column] = float(np.count_nonzero(available) > len(available) / 2)
            else:
                fill[column] = np.median(available)
        numeric = NumericTransform(self.kind, self.continuous, seed=self.seed)
        numeric.fit(np.where(observed, values, fill))
        self.fill, self.observed_counts, self.numeric = fill, counts, numeric
        return self

    def transform(self, inputs: ObservedInputs) -> np.ndarray:
        inputs.checked()
        if self.fill is None or self.numeric is None:
            raise ValueError("missingness transform must be fitted before inference")
        values = np.where(
            inputs.observed[:, : self.width], inputs.values[:, : self.width], self.fill
        )
        result = self.numeric.transform(values)
        if self.view == "imputation_missingness":
            indicators = ~inputs.observed[:, CORE_DIM::3]
            result = np.column_stack((result, indicators))
        if result.shape[1] != len(self.feature_names) or not np.isfinite(result).all():
            raise ValueError("invalid transformed missingness feature matrix")
        return np.asarray(result, dtype=np.float64)

    def arrays(self) -> dict[str, np.ndarray]:
        if self.fill is None or self.observed_counts is None or self.numeric is None:
            raise ValueError("missingness transform must be fitted before serialization")
        return {
            "missingness_schema": np.asarray([1], dtype=np.int64),
            "missingness_view": np.asarray([VIEWS.index(self.view)], dtype=np.int64),
            "missingness_seed": np.asarray([self.seed], dtype=np.int64),
            "imputation_values": self.fill.copy(),
            "imputation_observed_counts": self.observed_counts.copy(),
            **self.numeric.arrays(),
        }

    @classmethod
    def from_arrays(cls, arrays: Mapping[str, np.ndarray]) -> MissingnessTransform:
        """Restore numeric-only parameters; callers must verify the artifact hash first."""
        data = {key: np.asarray(value).copy() for key, value in arrays.items()}
        if any(v.dtype.kind not in "fiu" or not np.isfinite(v).all() for v in data.values()):
            raise ValueError("missingness artifact must contain finite numeric arrays")

        def integer(key: str) -> int:
            value = data.get(key)
            if value is None or value.shape != (1,) or value.dtype.kind not in "iu":
                raise ValueError(f"invalid integer artifact parameter: {key}")
            return int(value[0])

        if integer("missingness_schema") != 1:
            raise ValueError("unsupported missingness artifact schema")
        view, kind = integer("missingness_view"), integer("transform_kind_code")
        if not 0 <= view < len(VIEWS) or not 0 <= kind < len(KINDS):
            raise ValueError("invalid missingness artifact view or transform")
        instance = cls(VIEWS[view], KINDS[kind], seed=integer("missingness_seed"))
        if integer("transform_dimension") != instance.width:
            raise ValueError("missingness artifact feature dimension mismatch")
        expected = {
            "missingness_schema",
            "missingness_view",
            "missingness_seed",
            "imputation_values",
            "imputation_observed_counts",
            "transform_kind_code",
            "transform_dimension",
            "transform_continuous_indices",
        }
        if instance.kind == "quantile_normal":
            expected |= {"transform_quantiles", "transform_references"}
        else:
            expected |= {"transform_center", "transform_scale"}
            if instance.kind == "clip_robust":
                expected |= {"transform_clip_lower", "transform_clip_upper"}
        if set(data) != expected:
            raise ValueError("missingness artifact has missing or unexpected arrays")
        fill, counts = data["imputation_values"], data["imputation_observed_counts"]
        if (
            fill.shape != (instance.width,)
            or counts.shape != fill.shape
            or counts.dtype.kind not in "iu"
            or (counts < 0).any()
            or (counts[:CORE_DIM] < 1).any()
            or (counts[:CORE_DIM] != counts[0]).any()
            or (counts > counts[0]).any()
        ):
            raise ValueError("invalid imputation parameters")
        if (fill[counts == 0] != 0).any() or (
            instance.width > CORE_DIM and not np.isin(fill[list(DIRECTION_INDICES)], [0, 1]).all()
        ):
            raise ValueError("invalid empty-feature fallback or binary imputation")
        indices = data["transform_continuous_indices"]
        if indices.dtype.kind not in "iu" or not np.array_equal(indices, instance.continuous):
            raise ValueError("numeric artifact indices differ from fixed feature order")
        numeric = NumericTransform(instance.kind, instance.continuous, seed=instance.seed)
        numeric.parameters = {
            k.removeprefix("transform_"): v for k, v in data.items() if k.startswith("transform_")
        }
        dimension = len(instance.continuous)
        if instance.kind == "quantile_normal":
            quantiles = data["transform_quantiles"]
            references = data["transform_references"]
            if (
                quantiles.ndim != 2
                or quantiles.shape[1] != dimension
                or not 1 <= len(quantiles) <= 100
                or references.shape != (len(quantiles),)
                or (np.diff(quantiles, axis=0) < 0).any()
                or not np.array_equal(references, np.linspace(0, 1, len(quantiles)))
            ):
                raise ValueError("invalid quantile transform parameters")
            transformer = QuantileTransformer(output_distribution="normal", subsample=None)
            transformer.quantiles_, transformer.references_ = quantiles, references
            transformer.n_quantiles_, transformer.n_features_in_ = len(quantiles), dimension
            numeric.quantile = transformer
        else:
            for name in ("center", "scale"):
                if data[f"transform_{name}"].shape != (dimension,):
                    raise ValueError("invalid numeric transform parameter shape")
            if (data["transform_scale"] <= 0).any():
                raise ValueError("numeric scales must be positive")
            if instance.kind == "clip_robust":
                lower, upper = data["transform_clip_lower"], data["transform_clip_upper"]
                if (
                    lower.shape != (dimension,)
                    or upper.shape != lower.shape
                    or (lower > upper).any()
                ):
                    raise ValueError("invalid numeric clipping bounds")
        instance.fill, instance.observed_counts, instance.numeric = fill, counts, numeric
        return instance
