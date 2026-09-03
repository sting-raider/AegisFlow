"""Execute the immutable DEV2-ORIGIN-002 benign environment diagnostic."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import platform
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Any

import numpy as np
import torch

from scripts.verify_registered_research_v2 import verify as verify_family_report
from training.v2.models import FusionNet
from training.v2.origin_probe import evaluate_view
from training.v2.provenance import (
    canonical_digest,
    clean_execution_commit,
    load_verified_preparation,
    partition_provenance,
    read_object,
    sha256_file,
    verify_capture_pool,
    write_new_json,
)
from training.v2.registered_family import Predictor, make_partitions, validate_model_inputs
from training.v2.registered_family import load_registration as load_family_config
from training.v2.tensors import SequenceRecord, build_dataset, deduplicate_records

ROOT = Path(__file__).resolve().parents[2]
REGISTRATION_PATH = "configs/research-v2/registered/DEV2-ORIGIN-002.json"
REGISTRATION_SHA256 = "eb5a5c35df3dc5576bc50c1b73324a546794d20ccf8716518ffd1cab577cbecd"


def text_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def load_registration(root: Path) -> dict[str, Any]:
    path = root / REGISTRATION_PATH
    if text_digest(path) != REGISTRATION_SHA256:
        raise ValueError("origin registration differs from this versioned runner")
    config = read_object(path)
    for name in ("protocol", "preparation", "encoder_report"):
        binding = config[name]
        if text_digest(root / binding["path"]) != binding["sha256"]:
            raise ValueError(f"origin registration {name} binding changed")
    if config["views"] != [
        "aggregate",
        "numerical_core",
        "sequence_mask",
        "sequence_aggregate",
        "missingness_only",
        "embedding_c_and_c",
        "embedding_ddos",
        "embedding_port_scan",
    ] or config["transforms"] != ["standard", "robust", "clip_robust", "quantile_normal"]:
        raise ValueError("origin view/transform matrix differs from implemented protocol")
    return config


def load_frozen_predictor(
    path: Path, metadata: Mapping[str, Any], family_config: Mapping[str, Any]
) -> Predictor:
    if (
        path.name != metadata["file"]
        or sha256_file(path) != metadata["sha256"]
        or path.stat().st_size != metadata["bytes"]
    ):
        raise ValueError("frozen encoder artifact hash/size mismatch")
    model = FusionNet(
        max_length=family_config["representation"]["sequence_max_length"],
        features_per_packet=len(family_config["representation"]["sequence_channels"]),
        aggregate_dim=len(family_config["representation"]["aggregate_features"]),
        encoder=family_config["model"]["encoder"],
        embedding_dim=family_config["model"]["sequence_embedding_dim"],
    )
    state_keys = set(model.state_dict())
    auxiliary = {"preprocessing_center", "preprocessing_scale", "ood_center", "ood_inverse"}
    with np.load(path, allow_pickle=False) as arrays:
        if set(arrays.files) != state_keys | auxiliary:
            raise ValueError("frozen encoder artifact arrays differ from model contract")
        state = {key: torch.from_numpy(np.array(arrays[key], copy=True)) for key in state_keys}
        center, scale = (
            np.array(arrays["preprocessing_center"]),
            np.array(arrays["preprocessing_scale"]),
        )
        ood_center, ood_inverse = np.array(arrays["ood_center"]), np.array(arrays["ood_inverse"])
    if not all(torch.isfinite(value).all() for value in state.values()) or not all(
        np.isfinite(value).all() for value in [center, scale, ood_center, ood_inverse]
    ):
        raise ValueError("nonfinite frozen encoder artifact")
    model.load_state_dict(state, strict=True)
    model.eval()
    for parameter in model.parameters():
        parameter.requires_grad_(False)
    return Predictor(model, center, scale, ood_center, ood_inverse)


def admit_records(
    records: Sequence[SequenceRecord],
    config: Mapping[str, Any],
    family_report: Mapping[str, Any],
    predictors: Mapping[str, Predictor],
) -> list[SequenceRecord]:
    scenarios = config["input"]["scenarios"]
    admitted = [
        record
        for record in records
        if record["scenario"] in scenarios and record["binary_label"] == "benign"
    ]
    actual = [sum(record["scenario"] == scenario for record in admitted) for scenario in scenarios]
    if actual != config["input"]["expected_counts"] or any(
        r["family"] != "benign" for r in admitted
    ):
        raise ValueError("origin input counts or benign labels differ from registration")
    admitted_ids = {record["event_id"] for record in admitted}
    admitted_dataset = build_dataset(admitted)
    admitted_inputs = {
        (sequence.tobytes(), mask.tobytes(), aggregate.tobytes())
        for sequence, mask, aggregate in zip(
            admitted_dataset.sequence,
            admitted_dataset.mask,
            admitted_dataset.aggregate,
            strict=True,
        )
    }
    family_config = family_report["registration"]
    for family in family_config["splits"]["held_family_attack_scenarios"]:
        partitions = make_partitions(
            records, family_config, family, family_config["splits"]["site_orientations"][0]
        )
        fit = partitions["fit"]
        reference = next(
            rotation["partition_provenance"]["fit"]
            for rotation in family_report["rotations"]
            if rotation["rotation"] == f"{family}_site_1"
        )
        if partition_provenance(fit) != reference:
            raise ValueError("reconstructed encoder fitting differs from bound family report")
        if admitted_ids & {record["event_id"] for record in fit}:
            raise ValueError("origin input event overlaps encoder fitting")
        fit_dataset = build_dataset(fit)
        predictor = predictors[family]
        validate_model_inputs(
            {"fit": fit_dataset, "origin": admitted_dataset}, predictor.center, predictor.scale
        )
        fit_inputs = {
            (sequence.tobytes(), mask.tobytes(), aggregate.tobytes())
            for sequence, mask, aggregate in zip(
                fit_dataset.sequence, fit_dataset.mask, fit_dataset.aggregate, strict=True
            )
        }
        if admitted_inputs & fit_inputs:
            raise ValueError("origin input model vector overlaps encoder fitting")
    return admitted


def build_views(
    records: Sequence[SequenceRecord], predictors: Mapping[str, Predictor]
) -> tuple[dict[str, tuple[np.ndarray, list[int]]], dict[str, float]]:
    shared_start = perf_counter()
    dataset = build_dataset(records)
    sequence = (
        (dataset.sequence * dataset.mask[..., None]).reshape(len(records), -1).astype(np.float64)
    )
    mask = dataset.mask.astype(np.float64)
    aggregate = dataset.aggregate.astype(np.float64)
    sequence_continuous = [packet * 4 + channel for packet in range(20) for channel in (0, 1)]
    views: dict[str, tuple[np.ndarray, list[int]]] = {}
    elapsed: dict[str, float] = {"shared_tensor_build_seconds": perf_counter() - shared_start}

    def add(name: str, factory: Any, continuous: list[int]) -> None:
        start = perf_counter()
        matrix = np.asarray(factory(), dtype=np.float64)
        elapsed[name] = perf_counter() - start
        views[name] = (matrix, continuous)

    add("aggregate", lambda: aggregate, list(range(9)))
    add("numerical_core", lambda: aggregate[:, :9], list(range(9)))
    add("sequence_mask", lambda: np.concatenate((sequence, mask), axis=1), sequence_continuous)
    add(
        "sequence_aggregate",
        lambda: np.concatenate((sequence, mask, aggregate), axis=1),
        sequence_continuous + list(range(100, 109)),
    )
    add("missingness_only", lambda: np.concatenate((mask, aggregate[:, 13:14]), axis=1), [])
    for family, predictor in predictors.items():
        add(
            f"embedding_{family}",
            lambda predictor=predictor: predictor.embeddings(dataset),
            list(range(48)),
        )
    return views, elapsed


def verify_probe_artifacts(output: Path, results: Sequence[Mapping[str, Any]]) -> int:
    count = 0
    declared: set[str] = set()
    for view in results:
        for transform in view["transforms"]:
            for fold in transform["folds"]:
                if fold["status"] != "evaluated":
                    continue
                metadata = fold["artifact"]
                path = output / metadata["file"]
                if path.name in declared or path.resolve().parent != output.resolve():
                    raise ValueError("duplicate or escaping probe artifact")
                declared.add(path.name)
                if (
                    sha256_file(path) != metadata["sha256"]
                    or path.stat().st_size != metadata["bytes"]
                ):
                    raise ValueError("probe artifact hash/size mismatch")
                with np.load(path, allow_pickle=False) as arrays:
                    if set(arrays.files) != set(metadata["arrays"]) or any(
                        list(arrays[key].shape) != meta["shape"]
                        or str(arrays[key].dtype) != meta["dtype"]
                        or not np.isfinite(arrays[key]).all()
                        for key, meta in metadata["arrays"].items()
                    ):
                        raise ValueError("probe artifact arrays differ from report")
                count += 1
    actual = {path.name for path in output.glob("*.npz")}
    if actual != declared:
        raise ValueError("unbound probe artifacts in result directory")
    return count


def run(prepared_manifest: Path, pcaps: Path, family_artifacts: Path, output: Path) -> Path:
    if output.exists():
        raise FileExistsError("refusing to reuse an origin experiment evidence directory")
    commit = clean_execution_commit(ROOT)
    config = load_registration(ROOT)
    if text_digest(prepared_manifest) != config["preparation"]["sha256"]:
        raise ValueError("local preparation differs from origin registration")
    verify_capture_pool(ROOT, pcaps)
    family_report = verify_family_report(ROOT, artifact_directory=family_artifacts)
    records = deduplicate_records(load_verified_preparation(ROOT, prepared_manifest))
    family_config = load_family_config(ROOT)
    predictors = {}
    for filename in config["encoder_report"]["artifacts"]:
        family = filename.removesuffix("_site_1.npz")
        metadata = next(
            rotation["artifact"]
            for rotation in family_report["rotations"]
            if rotation["rotation"] == filename.removesuffix(".npz")
        )
        predictors[family] = load_frozen_predictor(
            family_artifacts / filename, metadata, family_config
        )
    torch.set_num_threads(config["execution"]["torch_threads"])
    admitted = admit_records(records, config, family_report, predictors)
    labels = np.asarray(
        [config["input"]["scenarios"].index(record["scenario"]) for record in admitted],
        dtype=np.int64,
    )
    output.mkdir(parents=True, exist_ok=False)
    started = perf_counter()
    started_at = datetime.now(UTC).isoformat()
    views, build_times = build_views(admitted, predictors)
    if list(views) != config["views"]:
        raise ValueError("constructed origin views differ from registration")
    results = []
    for name in config["views"]:
        print(f"running {name}", flush=True)
        matrix, continuous = views[name]
        result = evaluate_view(name, matrix, continuous, labels, admitted, config, output)
        result["feature_build_seconds"] = build_times[name]
        write_new_json(output / f"{name}.json", result)
        results.append(result)
        evaluated = [
            item.get("balanced_accuracy_mean")
            for item in result["transforms"]
            if item["status"] == "evaluated"
        ]
        print(f"completed {name}: {evaluated or result.get('reason')}", flush=True)
    artifact_count = verify_probe_artifacts(output, results)
    verify_family_report(ROOT, artifact_directory=family_artifacts)
    verify_capture_pool(ROOT, pcaps)
    final = deduplicate_records(load_verified_preparation(ROOT, prepared_manifest))
    if (
        canonical_digest(final) != canonical_digest(records)
        or load_registration(ROOT) != config
        or clean_execution_commit(ROOT) != commit
    ):
        raise ValueError("origin code, data, or configuration changed during execution")
    path = output / "report.json"
    write_new_json(
        path,
        {
            "schema_version": "1.0.0",
            "experiment_id": config["experiment_id"],
            "execution_status": "completed",
            "scientific_status": "development_origin_diagnostic_only",
            "code_commit": commit,
            "registration_sha256_utf8_lf": REGISTRATION_SHA256,
            "registration": config,
            "preparation_manifest": read_object(prepared_manifest),
            "encoder_report": {
                "path": config["encoder_report"]["path"],
                "sha256": config["encoder_report"]["sha256"],
                "execution_commit": config["encoder_report"]["execution_commit"],
            },
            "input_provenance": partition_provenance(admitted),
            "origin_mapping": {
                str(index): scenario for index, scenario in enumerate(config["input"]["scenarios"])
            },
            "input_counts": dict(
                sorted(Counter(record["scenario"] for record in admitted).items())
            ),
            "started_at": started_at,
            "completed_at": datetime.now(UTC).isoformat(),
            "elapsed_seconds": perf_counter() - started,
            "local_probe_artifacts": artifact_count,
            "shared_tensor_build_seconds": build_times["shared_tensor_build_seconds"],
            "environment": {
                "python": platform.python_version(),
                "platform": platform.system(),
                "machine": platform.machine(),
                "torch_threads": torch.get_num_threads(),
                "dependencies": {
                    name: importlib.metadata.version(name)
                    for name in ("numpy", "torch", "scikit-learn", "psutil")
                },
            },
            "views": results,
            "limitations": [
                "Three benign captures do not represent production environment diversity.",
                "Within-capture correlation makes row-wise cross-validation optimistic.",
                "A linear probe score below 0.90 is not proof of representation invariance.",
                "View-specific exact groups mean view results are not perfectly paired folds.",
                "Probe inference timing excludes feature and frozen-encoder generation.",
                "This diagnostic does not measure attack detection, unknown recall, or benign FPR.",
                "No detector training, threshold tuning, final evaluation, or promotion occurs.",
            ],
        },
    )
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared-manifest", required=True, type=Path)
    parser.add_argument("--pcap-dir", required=True, type=Path)
    parser.add_argument("--family-artifact-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    print(run(args.prepared_manifest, args.pcap_dir, args.family_artifact_dir, args.output_dir))


if __name__ == "__main__":
    main()
