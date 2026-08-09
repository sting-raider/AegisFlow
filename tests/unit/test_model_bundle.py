from __future__ import annotations

import shutil
from pathlib import Path

import numpy as np
import pytest

from packages.detection import DetectionEngine, HybridPredictor
from packages.features import flow_to_vector
from packages.model_bundle import BundleError, ModelBundle, load_production_bundle
from services.sensor import DemoAdapter


def test_training_and_inference_transform_are_identical(bundle: ModelBundle) -> None:
    raw = flow_to_vector(next(iter(DemoAdapter().flows())))
    before = bundle.preprocessor.transform(raw)
    reloaded = ModelBundle.load(bundle.root)
    after = reloaded.preprocessor.transform(raw)
    np.testing.assert_allclose(before, after)
    assert not np.allclose(after, np.zeros_like(after))
    assert reloaded.autoencoder is not None
    assert reloaded.anomaly_calibration is not None


def test_generated_bundle_text_artifacts_use_platform_independent_lf(
    bundle: ModelBundle,
) -> None:
    text_artifacts = [
        "feature_schema.json",
        "label_mapping.json",
        "thresholds.json",
        "calibration.json",
        "metrics.json",
        "training_config.yaml",
        "training_data_manifest.json",
        "manifest.json",
        "checksums.sha256",
    ]
    for filename in text_artifacts:
        assert b"\r\n" not in (bundle.root / filename).read_bytes(), filename


def test_detection_reports_empirical_anomaly_percentile(bundle: ModelBundle) -> None:
    flow = next(iter(DemoAdapter().flows()))
    result = DetectionEngine(bundle).detect(flow)
    assert bundle.anomaly_calibration is not None
    assert result.anomaly_percentile == pytest.approx(
        bundle.anomaly_calibration.percentile(result.anomaly_score), abs=1e-7
    )


def test_runtime_single_flow_and_shared_batch_hybrid_paths_are_identical(
    bundle: ModelBundle,
) -> None:
    flows = list(DemoAdapter().flows())
    raw = np.vstack([flow_to_vector(flow) for flow in flows])
    contexts = np.asarray(
        [
            min(float(flow.protocol_metadata.get("distinct_destination_ports", 0)) / 25.0, 1.0)
            for flow in flows
        ]
    )
    batch = HybridPredictor(bundle).predict(raw, contextual_scores=contexts)
    singles = [DetectionEngine(bundle).detect(flow) for flow in flows]

    np.testing.assert_allclose(
        batch.anomaly_scores,
        [result.anomaly_score for result in singles],
        atol=1e-8,
    )
    np.testing.assert_allclose(
        batch.anomaly_percentiles,
        [result.anomaly_percentile for result in singles],
        atol=1e-8,
    )
    assert [outcome.verdict for outcome in batch.outcomes] == [result.verdict for result in singles]
    assert [outcome.risk for outcome in batch.outcomes] == [
        result.final_risk_score for result in singles
    ]


def test_detection_engine_batch_preserves_single_flow_results(bundle: ModelBundle) -> None:
    flows = list(DemoAdapter().flows())
    engine = DetectionEngine(bundle)

    batched = engine.detect_batch(flows)
    singles = [engine.detect(flow) for flow in flows]

    assert len(batched) == len(singles)
    numeric = {
        "known_attack_probability",
        "classifier_confidence",
        "anomaly_score",
        "anomaly_percentile",
        "open_set_score",
        "reconstruction_error",
        "reconstruction_score",
        "signature_score",
        "contextual_score",
        "final_risk_score",
    }
    excluded = {"timestamp", "inference_latency_ms", "processing_latency_ms", *numeric}
    assert [result.model_dump(exclude=excluded) for result in batched] == [
        result.model_dump(exclude=excluded) for result in singles
    ]
    for field in numeric:
        np.testing.assert_allclose(
            [getattr(result, field) for result in batched],
            [getattr(result, field) for result in singles],
            atol=1e-6,
        )
    for batch_result, single_result in zip(batched, singles, strict=True):
        assert batch_result.class_probabilities == pytest.approx(
            single_result.class_probabilities, abs=1e-7
        )
    assert all(result.inference_latency_ms >= 0 for result in batched)
    assert all(result.processing_latency_ms >= result.inference_latency_ms for result in batched)


def test_corrupted_artifact_fails_before_deserialization(
    bundle: ModelBundle, tmp_path: Path
) -> None:
    target = tmp_path / "corrupt" / bundle.version
    shutil.copytree(bundle.root, target)
    with (target / "classifier.joblib").open("ab") as stream:
        stream.write(b"tampered")
    with pytest.raises(BundleError, match="checksum mismatch"):
        ModelBundle.load(target)


def test_incompatible_feature_order_fails(bundle: ModelBundle, tmp_path: Path) -> None:
    target = tmp_path / "schema" / bundle.version
    shutil.copytree(bundle.root, target)
    schema = (target / "feature_schema.json").read_text(encoding="utf-8")
    (target / "feature_schema.json").write_text(
        schema.replace('"duration_ms"', '"wrong_feature"', 1), encoding="utf-8"
    )
    with pytest.raises(BundleError, match="checksum mismatch"):
        ModelBundle.load(target)


def test_manifest_artifact_hash_is_independently_verified(
    bundle: ModelBundle, tmp_path: Path
) -> None:
    import hashlib
    import json

    target = tmp_path / bundle.version
    shutil.copytree(bundle.root, target)
    manifest_path = target / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifact_hashes"]["classifier.joblib"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    checksum_path = target / "checksums.sha256"
    rows = []
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        _, filename = line.split(maxsplit=1)
        path = target / filename
        rows.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {filename}\n")
    checksum_path.write_text("".join(rows), encoding="utf-8")
    with pytest.raises(BundleError, match="manifest artifact hash mismatch"):
        ModelBundle.load(target)


def test_invalid_empirical_calibration_fails_after_integrity_checks(
    bundle: ModelBundle, tmp_path: Path
) -> None:
    import hashlib
    import json

    target = tmp_path / bundle.version
    shutil.copytree(bundle.root, target)
    calibration_path = target / "calibration.json"
    calibration = json.loads(calibration_path.read_text(encoding="utf-8"))
    calibration["combined_anomaly_score"]["probabilities"][-1] = 0.9
    calibration_path.write_text(json.dumps(calibration, indent=2) + "\n", encoding="utf-8")
    manifest_path = target / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifact_hashes"]["calibration.json"] = hashlib.sha256(
        calibration_path.read_bytes()
    ).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    checksum_path = target / "checksums.sha256"
    filenames = [
        line.split(maxsplit=1)[1] for line in checksum_path.read_text(encoding="utf-8").splitlines()
    ]
    checksum_path.write_text(
        "".join(
            f"{hashlib.sha256((target / filename).read_bytes()).hexdigest()}  {filename}\n"
            for filename in filenames
        ),
        encoding="utf-8",
    )

    with pytest.raises(BundleError, match="invalid empirical anomaly calibration"):
        ModelBundle.load(target)


def test_corrupt_production_version_falls_back_to_previous_valid(
    registry: Path, bundle: ModelBundle
) -> None:
    import json

    pointer = registry / "aegisflow-smoke" / "production.json"
    original = pointer.read_text(encoding="utf-8")
    try:
        pointer.write_text(
            json.dumps({"version": "corrupt", "history": [bundle.version]}) + "\n",
            encoding="utf-8",
        )
        loaded = load_production_bundle(registry)
        assert loaded.version == bundle.version
        assert loaded.load_warning is not None
        assert "corrupt" in loaded.load_warning
    finally:
        pointer.write_text(original, encoding="utf-8")
