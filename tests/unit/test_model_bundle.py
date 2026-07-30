from __future__ import annotations

import shutil
from pathlib import Path

import numpy as np
import pytest

from packages.features import flow_to_vector
from packages.model_bundle import BundleError, ModelBundle
from services.sensor import DemoAdapter


def test_training_and_inference_transform_are_identical(bundle: ModelBundle) -> None:
    raw = flow_to_vector(next(iter(DemoAdapter().flows())))
    before = bundle.preprocessor.transform(raw)
    reloaded = ModelBundle.load(bundle.root)
    after = reloaded.preprocessor.transform(raw)
    np.testing.assert_allclose(before, after)
    assert not np.allclose(after, np.zeros_like(after))


def test_corrupted_artifact_fails_before_deserialization(
    bundle: ModelBundle, tmp_path: Path
) -> None:
    target = tmp_path / "corrupt"
    shutil.copytree(bundle.root, target)
    with (target / "classifier.joblib").open("ab") as stream:
        stream.write(b"tampered")
    with pytest.raises(BundleError, match="checksum mismatch"):
        ModelBundle.load(target)


def test_incompatible_feature_order_fails(bundle: ModelBundle, tmp_path: Path) -> None:
    target = tmp_path / "schema"
    shutil.copytree(bundle.root, target)
    schema = (target / "feature_schema.json").read_text(encoding="utf-8")
    (target / "feature_schema.json").write_text(
        schema.replace('"duration_ms"', '"wrong_feature"', 1), encoding="utf-8"
    )
    with pytest.raises(BundleError, match="checksum mismatch"):
        ModelBundle.load(target)
