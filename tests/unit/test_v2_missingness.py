from __future__ import annotations

from pathlib import Path
from shutil import copyfile
from typing import cast

import numpy as np
import pytest

from packages.detection_v2.sequences import sequence_arrays
from training.v2.missingness import (
    CORE_DIM,
    DIRECTION_INDICES,
    INPUT_NAMES,
    VIEWS,
    MissingnessTransform,
    ObservedInputs,
    observation_inputs,
)
from training.v2.origin_probe import KINDS
from training.v2.tensors import SequenceRecord
from training.v2.transfer_support import (
    REGISTRATION_PATH,
    common_support,
    load_registration,
    transfer_partitions,
)


def inputs(rows: int = 30) -> ObservedInputs:
    generator = np.random.default_rng(718)
    values = generator.normal(size=(rows, len(INPUT_NAMES)))
    values[:, DIRECTION_INDICES] = generator.integers(0, 2, size=(rows, 20))
    observed = np.ones(values.shape, dtype=bool)
    for index in range(rows):
        observed[index, CORE_DIM + 3 * (index % 21) :] = False
    values[~observed] = 0
    return ObservedInputs(values, observed).checked()


@pytest.mark.parametrize("view", VIEWS)
@pytest.mark.parametrize("kind", KINDS)
def test_missingness_transforms_keep_fixed_geometry_and_train_only_state(
    view: str,
    kind: str,
) -> None:
    train = inputs()
    before = train.values.copy()
    transform = MissingnessTransform(view, kind, seed=71).fit(train)
    saved = transform.arrays()
    result = transform.transform(train)
    assert result.shape == (
        30,
        {"portable_intersection": 9, "imputation_only": 69, "imputation_missingness": 89}[view],
    )
    if view != "portable_intersection":
        assert np.isin(result[:, DIRECTION_INDICES], [0, 1]).all()
    if view == "imputation_missingness":
        np.testing.assert_array_equal(result[:, 69:], ~train.observed[:, CORE_DIM::3])
    extremes = ObservedInputs(train.values * 1e8, train.observed.copy())
    extremes.values[:, DIRECTION_INDICES] = train.values[:, DIRECTION_INDICES]
    assert np.isfinite(transform.transform(extremes)).all()
    for key, array in saved.items():
        np.testing.assert_array_equal(transform.arrays()[key], array)
    np.testing.assert_array_equal(train.values, before)
    singles = np.concatenate(
        [transform.transform(train.subset(np.asarray([i]))) for i in range(len(train.values))]
    )
    np.testing.assert_allclose(singles, result, atol=0, rtol=0)


def test_imputation_uses_only_observed_values_and_binary_mode_not_median() -> None:
    values = np.zeros((4, len(INPUT_NAMES)))
    observed = np.ones(values.shape, dtype=bool)
    observed[:, CORE_DIM + 3 :] = False
    observed[3, CORE_DIM:] = False
    values[:3, CORE_DIM] = [0, 2, 100]
    values[:3, CORE_DIM + 2] = [0, 1, 1]
    train = ObservedInputs(values, observed)
    transform = MissingnessTransform("imputation_missingness", "standard", seed=71).fit(train)
    assert transform.fill[CORE_DIM] == 2  # observed zero is data, not absence
    assert transform.fill[CORE_DIM + 2] == 1
    assert transform.observed_counts[CORE_DIM] == 3
    assert np.all(transform.fill[CORE_DIM + 3 :] == 0)
    assert np.all(transform.observed_counts[CORE_DIM + 3 :] == 0)
    assert transform.transform(train).shape == (4, 89)  # no empty-column removal


def test_binary_mode_ties_use_declared_zero_fallback() -> None:
    train = inputs(2)
    train.observed[:, CORE_DIM : CORE_DIM + 3] = True
    train.values[:, CORE_DIM + 2] = [0, 1]
    transform = MissingnessTransform("imputation_only", "standard", seed=71).fit(train)
    assert transform.fill[CORE_DIM + 2] == 0


@pytest.mark.parametrize("view", VIEWS)
@pytest.mark.parametrize("kind", KINDS)
def test_numeric_only_roundtrip_reconstructs_identical_inference(
    view: str,
    kind: str,
    tmp_path: Path,
) -> None:
    train = inputs()
    transform = MissingnessTransform(view, kind, seed=71).fit(train)
    path = tmp_path / "preprocessing.npz"
    np.savez_compressed(path, **transform.arrays())
    with np.load(path, allow_pickle=False) as archive:
        restored = MissingnessTransform.from_arrays(dict(archive))
    assert restored.feature_names == transform.feature_names
    np.testing.assert_array_equal(restored.transform(train), transform.transform(train))


@pytest.mark.parametrize(
    "corruption",
    [
        "nan",
        "inf_masked",
        "nonzero_masked",
        "core_missing",
        "unaligned",
        "nonprefix",
        "direction",
        "mask_type",
    ],
)
def test_malformed_or_incompatible_inputs_never_become_imputation(corruption: str) -> None:
    batch = inputs()
    if corruption == "nan":
        batch.values[0, 0] = np.nan
    elif corruption == "inf_masked":
        batch.values[0, CORE_DIM] = np.inf
    elif corruption == "nonzero_masked":
        batch.values[0, CORE_DIM] = 17
    elif corruption == "core_missing":
        batch.observed[0, 0] = False
    elif corruption == "unaligned":
        batch.observed[0, CORE_DIM] = True
    elif corruption == "nonprefix":
        batch.observed[0, CORE_DIM + 3 : CORE_DIM + 6] = True
    elif corruption == "direction":
        batch.values[20, CORE_DIM + 2] = 0.5
    else:
        batch = ObservedInputs(batch.values, batch.observed.astype(int))
    with pytest.raises(ValueError):
        MissingnessTransform("portable_intersection", "standard", seed=71).fit(batch)


def test_unfitted_and_empty_transforms_are_rejected() -> None:
    transform = MissingnessTransform("imputation_only", "standard", seed=71)
    with pytest.raises(ValueError, match="fitted"):
        transform.transform(inputs())
    with pytest.raises(ValueError, match="fitted"):
        transform.arrays()
    with pytest.raises(ValueError):
        transform.fit(ObservedInputs(np.zeros((0, 69)), np.zeros((0, 69), dtype=bool)))


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize(
    "parameter",
    ["extra", "missing", "wrong_shape", "nonfinite", "version", "indices", "binary", "counts"],
)
def test_numeric_artifact_loader_rejects_incompatible_parameters(kind: str, parameter: str) -> None:
    arrays = MissingnessTransform("imputation_only", kind, seed=71).fit(inputs()).arrays()
    if parameter == "extra":
        arrays["raw_row_ids"] = np.asarray([1])
    elif parameter == "missing":
        arrays.pop("imputation_values")
    elif parameter == "wrong_shape":
        arrays["transform_dimension"] = np.asarray([9])
    elif parameter == "nonfinite":
        arrays["imputation_values"][0] = np.nan
    elif parameter == "version":
        arrays["missingness_schema"][0] = 2
    elif parameter == "indices":
        arrays["transform_continuous_indices"][0] = 1
    elif parameter == "binary":
        arrays["imputation_values"][CORE_DIM + 2] = 0.5
    elif parameter == "counts":
        arrays["imputation_observed_counts"][0] = -1
    with pytest.raises(ValueError):
        MissingnessTransform.from_arrays(arrays)


def record() -> SequenceRecord:
    return cast(
        SequenceRecord,
        {
            "duration_ms": 100.0,
            "packets_forward": 2,
            "packets_reverse": 1,
            "bytes_forward": 100,
            "bytes_reverse": 200,
            "dst_port": 80,
            "protocol": "TCP",
            "seq_sizes": [10.0, 20.0, 30.0],
            "seq_directions": [1, -1, 1],
            "seq_iats_ms": [0.0, 1.0, 2.0],
        },
    )


def test_observation_views_share_runtime_features_and_exclude_source_or_label() -> None:
    first = record()
    second = {
        **first,
        "dst_port": 53000,
        "protocol": "UDP",
        "scenario": "changed",
        "family": "malicious",
        "event_id": "changed",
    }
    batch = observation_inputs([first, second])
    np.testing.assert_array_equal(batch.values[0], batch.values[1])
    tensor, mask = sequence_arrays(
        first["seq_sizes"], first["seq_directions"], first["seq_iats_ms"]
    )
    np.testing.assert_array_equal(batch.values[0, CORE_DIM:], tensor[:, :3].reshape(-1))
    np.testing.assert_array_equal(batch.observed[0, CORE_DIM:], np.repeat(mask.astype(bool), 3))
    np.testing.assert_array_equal(observation_inputs([first]).values[0], batch.values[0])
    assert batch.support()["observed_counts_by_feature"][CORE_DIM + 9] == 0
    assert batch.support()["rows_without_observed_packets"] == 0


def test_prepared_malformed_packet_fails_at_shared_encoder_boundary() -> None:
    item = record()
    item["seq_sizes"][1] = float("nan")
    with pytest.raises(ValueError, match="sizes"):
        observation_inputs([item])


def complete_record(index: int, scenario: str, family: str) -> SequenceRecord:
    item = record()
    item.update(
        {
            "event_id": f"event-{index:03d}",
            "scenario": scenario,
            "family": family,
            "binary_label": "benign" if family == "benign" else "malicious",
        }
    )
    item["duration_ms"] = float(index)
    item["seq_sizes"] = [float(index)]
    item["seq_directions"] = [1]
    item["seq_iats_ms"] = [0.0]
    return item


def test_common_support_excludes_source_aliases_and_label_ambiguity_without_selection() -> None:
    records = [
        complete_record(1, "source-a", "benign"),
        complete_record(1, "source-b", "benign"),  # cross-source portable-core alias
        complete_record(2, "source-a", "benign"),
        complete_record(2, "source-a", "ddos"),  # within-source reduced-view ambiguity
        complete_record(3, "source-a", "benign"),
        complete_record(3, "source-a", "benign"),
    ]
    records[1]["event_id"] = "shared-other-id"
    records[3]["event_id"] = "ambiguous-other-id"
    records[-1]["event_id"] = "event-999"
    records[-1]["seq_sizes"] = [300.0]  # optional variant, same portable core
    retained, report = common_support(list(reversed(records)))
    assert [row["event_id"] for row in retained] == ["event-003"]
    assert report["input_core_groups"] == 3
    assert report["cross_capture_groups"] == 1
    assert report["cross_capture_excluded"]["rows"] == 2
    assert report["within_capture_ambiguous_excluded"]["rows"] == 2
    assert report["within_capture_duplicate_rows"]["rows"] == 1
    assert report["groups_with_optional_packet_variants"] == 1


def test_common_support_refuses_bad_identity_or_labels() -> None:
    first, second = complete_record(1, "source", "benign"), complete_record(2, "source", "benign")
    second["event_id"] = first["event_id"]
    with pytest.raises(ValueError, match="event IDs"):
        common_support([first, second])
    first["binary_label"] = "unknown"
    with pytest.raises(ValueError, match="label"):
        common_support([first])


def test_transfer_partitions_are_capture_disjoint_and_attack_bearing() -> None:
    records = [
        complete_record(1, "train-a", "benign"),
        complete_record(2, "train-a", "ddos"),
        complete_record(3, "background", "benign"),
        complete_record(4, "target", "benign"),
        complete_record(5, "target", "c_and_c"),
        complete_record(6, "cal", "benign"),
        complete_record(7, "test", "benign"),
    ]
    result = transfer_partitions(
        records,
        sources=["train-a"],
        target="target",
        background_benign="background",
        orientation={"calibration": "cal", "benign_test": "test"},
        per_class_cap=10,
        seed=71,
    )
    assert {row["scenario"] for row in result["fit"]} == {"train-a", "background"}
    assert {row["binary_label"] for row in result["target"]} == {"benign", "malicious"}


@pytest.mark.parametrize("defect", ["role", "background", "target", "site"])
def test_transfer_partitions_fail_closed(defect: str) -> None:
    records = [
        complete_record(1, "train", "benign"),
        complete_record(2, "train", "ddos"),
        complete_record(3, "background", "benign"),
        complete_record(4, "target", "c_and_c"),
        complete_record(5, "cal", "benign"),
        complete_record(6, "test", "benign"),
    ]
    kwargs = {
        "sources": ["train"],
        "target": "target",
        "background_benign": "background",
        "orientation": {"calibration": "cal", "benign_test": "test"},
        "per_class_cap": 10,
        "seed": 71,
    }
    if defect == "role":
        kwargs["target"] = "train"
    elif defect == "background":
        records[2]["family"], records[2]["binary_label"] = "ddos", "malicious"
    elif defect == "target":
        records[3]["family"], records[3]["binary_label"] = "benign", "benign"
    else:
        records[4]["family"], records[4]["binary_label"] = "ddos", "malicious"
    with pytest.raises(ValueError):
        transfer_partitions(records, **kwargs)


def test_missingness_registration_fixes_unexecuted_matrix_and_input_order() -> None:
    config = load_registration(Path(__file__).resolve().parents[2])
    assert config["status"] == "registered_not_run"
    assert config["splits"]["expected_model_fits"] == 9 * len(VIEWS) * len(KINDS)
    assert config["splits"]["expected_site_evaluations"] == 216
    assert config["cohort"]["retained_rows"] == 6195
    assert not config["candidate_promotion_authorized"]


@pytest.mark.parametrize("field", ["registration", "protocol", "prepared_manifest"])
def test_missingness_registration_rejects_configuration_or_bound_input_changes(
    field: str,
    tmp_path: Path,
) -> None:
    root = Path(__file__).resolve().parents[2]
    config = load_registration(root)
    paths = {
        "registration": REGISTRATION_PATH,
        **{key: config[key]["path"] for key in ("protocol", "prepared_manifest")},
    }
    for relative in paths.values():
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        copyfile(root / relative, destination)
    with (tmp_path / paths[field]).open("a", encoding="utf-8") as stream:
        stream.write(" ")
    with pytest.raises(ValueError, match="registration"):
        load_registration(tmp_path)
