from __future__ import annotations

from pathlib import Path
from typing import cast

import numpy as np
import pytest
import torch

from training.v2.models import FusionNet
from training.v2.origin_probe import evaluate_view
from training.v2.registered_family import Predictor
from training.v2.registered_family import load_registration as family_config
from training.v2.registered_origin import load_frozen_predictor, load_registration, run
from training.v2.tensors import SequenceRecord

ROOT = Path(__file__).resolve().parents[2]


def test_origin_runner_loads_only_registered_matrix() -> None:
    config = load_registration(ROOT)
    assert len(config["views"]) == 8
    assert config["validation"]["folds"] == 5


def test_ineligible_origin_view_retains_group_ambiguity_evidence(tmp_path: Path) -> None:
    config = load_registration(ROOT)
    result = evaluate_view(
        "constant",
        np.ones((30, 2)),
        [],
        np.tile([0, 1, 2], 10),
        [cast(SequenceRecord, {})] * 30,
        config,
        tmp_path,
    )
    assert result["status"] == "ineligible_grouped_folds"
    assert result["grouping"]["groups"] == 1
    assert result["grouping"]["cross_origin_ambiguous_groups"] == 1
    assert result["transforms"] == []


def test_existing_origin_output_is_refused_before_any_training(tmp_path: Path) -> None:
    with pytest.raises(FileExistsError, match="reuse"):
        run(tmp_path / "missing", tmp_path / "missing", tmp_path / "missing", tmp_path)


def test_frozen_encoder_numeric_roundtrip_and_tampering(tmp_path: Path) -> None:
    model = FusionNet(max_length=20, features_per_packet=4, aggregate_dim=24)
    predictor = Predictor(model, np.zeros(24), np.ones(24), np.zeros(48), np.eye(48))
    path = tmp_path / "fixture.npz"
    metadata = predictor.save(path)
    restored = load_frozen_predictor(path, metadata, family_config(ROOT))
    assert not restored.model.training
    assert not any(parameter.requires_grad for parameter in restored.model.parameters())
    for key, value in model.state_dict().items():
        assert torch.equal(value, restored.model.state_dict()[key])
    metadata["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="hash"):
        load_frozen_predictor(path, metadata, family_config(ROOT))


def test_probe_fixture_retains_metrics_costs_and_local_numeric_parameters(tmp_path: Path) -> None:
    config = load_registration(ROOT)
    config["transforms"] = ["standard"]
    config["measurement"]["warmups"] = 1
    config["measurement"]["repetitions"] = 2
    config["measurement"]["batch_sizes"] = [1, 8]
    matrix = np.repeat(np.arange(30, dtype=float), 3).reshape(-1, 1)
    labels = np.tile([0, 1, 2], 30)
    records = [
        cast(
            SequenceRecord,
            {
                "event_id": f"fixture-{i}",
                "scenario": f"s-{label}",
                "family": "benign",
                "binary_label": "benign",
            },
        )
        for i, label in enumerate(labels.tolist())
    ]
    result = evaluate_view("fixture", matrix, [0], labels, records, config, tmp_path)
    entry = result["transforms"][0]
    assert entry["status"] == "evaluated"
    assert len(entry["folds"]) == 5
    assert entry["balanced_accuracy_mean"] == pytest.approx(1 / 3)
    for fold in entry["folds"]:
        assert fold["fit_seconds"] > 0
        assert fold["memory"]["rss_before_bytes"] > 0
        assert len(fold["inference"]) == 2
        with np.load(tmp_path / fold["artifact"]["file"], allow_pickle=False) as artifact:
            assert artifact["coefficient"].shape == (3, 1)
            assert np.array_equal(artifact["classes"], [0, 1, 2])


def test_origin_views_preserve_declared_dimensions_and_categorical_columns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from training.v2 import registered_origin
    from training.v2.tensors import V2Dataset

    dataset = V2Dataset(
        sequence=np.ones((3, 20, 4), dtype=np.float32),
        mask=np.ones((3, 20), dtype=np.float32),
        state=np.zeros((3, 8)),
        aggregate=np.ones((3, 24)),
        binary_label=np.zeros(3),
        family=["benign"] * 3,
        scenario=["fixture"] * 3,
        observability=["HIGH"] * 3,
        event_ids=["a", "b", "c"],
    )
    monkeypatch.setattr(registered_origin, "build_dataset", lambda _: dataset)

    class FrozenFixture:
        def embeddings(self, _dataset: V2Dataset) -> np.ndarray:
            return np.ones((3, 48))

    predictors = {
        name: cast(Predictor, FrozenFixture()) for name in ("c_and_c", "ddos", "port_scan")
    }
    views, timings = registered_origin.build_views([cast(SequenceRecord, {})] * 3, predictors)
    assert [matrix.shape[1] for matrix, _ in views.values()] == [24, 9, 100, 124, 21, 48, 48, 48]
    assert views["aggregate"][1] == list(range(9))
    assert views["missingness_only"][1] == []
    assert 2 not in views["sequence_mask"][1]  # direction is not numerically transformed
    assert 3 not in views["sequence_mask"][1]  # position retains its bounded geometry
    assert len(views["sequence_aggregate"][1]) == 49
    assert timings["shared_tensor_build_seconds"] >= 0


def test_failed_probe_fold_retains_elapsed_fit_cost(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sklearn.exceptions import ConvergenceWarning

    from training.v2 import origin_probe

    class NonconvergingProbe:
        def __init__(self, **kwargs: object) -> None:
            pass

        def fit(self, *args: object) -> None:
            raise ConvergenceWarning("controlled nonconverging fixture")

    monkeypatch.setattr(origin_probe, "LogisticRegression", NonconvergingProbe)
    config = load_registration(ROOT)
    config["transforms"] = ["standard"]
    matrix = np.repeat(np.arange(30, dtype=float), 3).reshape(-1, 1)
    labels = np.tile([0, 1, 2], 30)
    records = [
        cast(
            SequenceRecord,
            {
                "event_id": f"fixture-{i}",
                "scenario": f"s-{label}",
                "family": "benign",
                "binary_label": "benign",
            },
        )
        for i, label in enumerate(labels.tolist())
    ]
    result = evaluate_view("fixture", matrix, [0], labels, records, config, tmp_path)
    for fold in result["transforms"][0]["folds"]:
        assert fold["status"] == "ineligible"
        assert fold["fit_seconds"] > 0
