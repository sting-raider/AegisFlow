"""Execute only the preregistered DEV2-FAMILY-002 development matrix.

No production writes, frozen evaluations, data-driven configuration selection, or
per-row report exports. Local NPZ artifacts contain numeric model parameters only.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import math
import platform
import threading
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Any

import numpy as np
import psutil
import torch
from sklearn.metrics import average_precision_score, brier_score_loss, f1_score

from training.v2.calibration import threshold_for_fpr
from training.v2.models import FusionNet
from training.v2.partitions import assert_strict_family_rotation
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
from training.v2.run_cross_environment import (
    BATCH_SIZE,
    LEARNING_RATE,
    SEED,
    ece_score,
    fit_standardizer,
    torch_fit,
)
from training.v2.run_held_family import mahalanobis_distances, mahalanobis_fit, select_fit
from training.v2.tensors import SequenceRecord, V2Dataset, build_dataset, deduplicate_records

REGISTRATION_PATH = "configs/research-v2/registered/DEV2-FAMILY-002.json"
# Registered and published before this implementation. This deliberately versioned
# driver cannot silently accept a changed field it does not yet implement.
REGISTRATION_SHA256 = "442ea69203048d4e89e3689fe333cbcb5b3060201ba1dd86d5c7bc3f7bc47705"
ROOT = Path(__file__).resolve().parents[2]
VERDICTS = ("known_attack", "suspicious_unknown", "needs_review", "benign")


def text_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def load_registration(root: Path) -> dict[str, Any]:
    path = root / REGISTRATION_PATH
    if text_digest(path) != REGISTRATION_SHA256:
        raise ValueError("registration differs from the protocol implemented by this runner")
    config = read_object(path)
    for field in ("protocol", "prepared_manifest"):
        binding = config[field]
        if text_digest(root / binding["path"]) != binding["sha256"]:
            raise ValueError(f"registration {field} binding changed")
    # The reused trainer's defaults must not drift from the locked registration.
    if (SEED, BATCH_SIZE, LEARNING_RATE) != (
        config["execution"]["seed"],
        config["model"]["batch_size"],
        config["model"]["learning_rate"],
    ):
        raise ValueError("trainer constants differ from registration")
    return config


def validate_model_inputs(
    partitions: Mapping[str, V2Dataset],
    center: np.ndarray,
    scale: np.ndarray,
) -> None:
    """Also reject overlap introduced by actual float32 preprocessing/casting."""
    seen: set[tuple[bytes, bytes, bytes]] = set()
    for dataset in partitions.values():
        aggregate = ((dataset.aggregate - center) / scale).astype(np.float32)
        if not all(np.isfinite(a).all() for a in (dataset.sequence, dataset.mask, aggregate)):
            raise ValueError("nonfinite model input")
        for seq, mask, agg in zip(dataset.sequence, dataset.mask, aggregate, strict=True):
            fingerprint = (seq.tobytes(), mask.tobytes(), agg.tobytes())
            if fingerprint in seen:
                raise ValueError("duplicate preprocessed float32 model input in partitions")
            seen.add(fingerprint)


def verdicts(scores: np.ndarray, distances: np.ndarray, cuts: Mapping[str, float]) -> np.ndarray:
    if (
        scores.ndim != 1
        or scores.shape != distances.shape
        or not scores.size
        or not np.isfinite(scores).all()
        or not np.isfinite(distances).all()
        or (scores < 0).any()
        or (scores > 1).any()
        or (distances < 0).any()
    ):
        raise ValueError("invalid model scores or distances")
    if not all(math.isfinite(value) for value in cuts.values()):
        raise ValueError("nonfinite thresholds")
    if cuts["known_review"] > cuts["known_direct"] or cuts["ood_review"] > cuts["ood_direct"]:
        raise ValueError("review thresholds exceed direct thresholds")
    result = np.full(scores.shape, "benign", dtype="U18")
    result[(scores >= cuts["known_review"]) | (distances >= cuts["ood_review"])] = "needs_review"
    result[distances >= cuts["ood_direct"]] = "suspicious_unknown"
    result[scores >= cuts["known_direct"]] = "known_attack"
    return result


def rate_interval(flags: np.ndarray) -> dict[str, Any]:
    n = len(flags)
    if not n:
        raise ValueError("rate requires nonempty population")
    successes = int(flags.sum())
    p = successes / n
    z = 1.959963984540054
    denominator = 1 + z * z / n
    midpoint = (p + z * z / (2 * n)) / denominator
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denominator
    return {
        "rows": n,
        "count": successes,
        "rate": p,
        "wilson_95": [max(0.0, midpoint - margin), min(1.0, midpoint + margin)],
    }


def quantiles(values: np.ndarray) -> dict[str, float]:
    return dict(
        zip(
            ("min", "p25", "p50", "p75", "p95", "p99", "max"),
            map(float, np.quantile(values, [0, 0.25, 0.5, 0.75, 0.95, 0.99, 1])),
            strict=True,
        )
    )


def evaluate_scores(
    scores: np.ndarray,
    distances: np.ndarray,
    labels: np.ndarray,
    cuts: Mapping[str, float],
    *,
    calibration_distances: np.ndarray | None = None,
) -> dict[str, Any]:
    predicted = verdicts(scores, distances, cuts)
    if labels.shape != scores.shape or not np.isin(labels, [0, 1]).all():
        raise ValueError("invalid evaluation labels")
    direct = np.isin(predicted, ["known_attack", "suspicious_unknown"])
    result: dict[str, Any] = {
        "rows": len(labels),
        "four_verdict_counts": {name: int((predicted == name).sum()) for name in VERDICTS},
    }
    for name, label in (("benign", 0), ("attack", 1)):
        mask = labels == label
        if not mask.any():
            continue
        group: dict[str, Any] = {
            "rows": int(mask.sum()),
            "four_verdict_counts": {v: int((predicted[mask] == v).sum()) for v in VERDICTS},
            "direct_suspicious_unknown": rate_interval(predicted[mask] == "suspicious_unknown"),
            "direct_detection": rate_interval(direct[mask]),
            "detection_or_review": rate_interval(predicted[mask] != "benign"),
            "known_channel": rate_interval(scores[mask] >= cuts["known_direct"]),
            "ood_channel": rate_interval(distances[mask] >= cuts["ood_direct"]),
            "score_quantiles": quantiles(scores[mask]),
            "distance_quantiles": quantiles(distances[mask]),
        }
        if calibration_distances is not None:
            percentiles = np.searchsorted(
                np.sort(calibration_distances), distances[mask], side="right"
            ) / len(calibration_distances)
            group["ood_calibration_percentile_quantiles"] = quantiles(percentiles)
        if label == 0:
            group["direct_union_fpr"] = rate_interval(direct[mask])
            group["review_inclusive_rate"] = rate_interval(predicted[mask] != "benign")
            group["false_alerts_per_10000_benign"] = float(direct[mask].mean() * 10000)
            group["false_alerts_per_hour"] = None
        result[name] = group
    if len(np.unique(labels)) == 2:
        result["binary_metrics"] = {
            "positive_prediction": "known_attack_or_suspicious_unknown",
            "macro_f1": float(f1_score(labels, direct, average="macro", zero_division=0)),
            "weighted_f1": float(f1_score(labels, direct, average="weighted", zero_division=0)),
            "known_score_pr_auc": float(average_precision_score(labels, scores)),
            "known_score_brier": float(brier_score_loss(labels, scores)),
            "known_score_ece_10_equal_width_bins": ece_score(scores, labels),
        }
    return result


class MemorySampler:
    """Sample current-process RSS, explicitly not a guaranteed OS peak counter."""

    def __init__(self) -> None:
        self.process = psutil.Process()
        self.before = self.process.memory_info().rss
        self.peak = self.before
        self.samples = 0
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._sample, daemon=True)

    def _sample(self) -> None:
        while not self.stop.wait(0.01):
            self.peak = max(self.peak, self.process.memory_info().rss)
            self.samples += 1

    def finish(self) -> dict[str, int | str]:
        self.stop.set()
        self.thread.join()
        after = self.process.memory_info().rss
        return {
            "scope": "current_process_including_loaded_data_not_incremental_model_size",
            "rss_before_bytes": self.before,
            "rss_after_bytes": after,
            "sampled_peak_rss_bytes": max(self.peak, after),
            "sampling_interval_ms": 10,
            "samples": self.samples,
        }


class Predictor:
    def __init__(
        self,
        model: FusionNet,
        center: np.ndarray,
        scale: np.ndarray,
        ood_center: np.ndarray,
        ood_inverse: np.ndarray,
    ) -> None:
        self.model = model
        self.center = center
        self.scale = scale
        self.ood_center = ood_center
        self.ood_inverse = ood_inverse

    def embeddings(self, dataset: V2Dataset) -> np.ndarray:
        with torch.no_grad():
            embedding = self.model.embed(
                torch.from_numpy(dataset.sequence),
                torch.from_numpy(dataset.mask),
                torch.from_numpy(
                    ((dataset.aggregate - self.center) / self.scale).astype(np.float32)
                ),
            )
        return np.asarray(embedding.numpy(), dtype=np.float64)

    def score(self, records: Sequence[SequenceRecord]) -> tuple[np.ndarray, np.ndarray]:
        # Deliberately includes shared tensor construction, preprocessing and OOD.
        embeddings = self.embeddings(build_dataset(records))
        with torch.no_grad():
            logits = self.model.head(torch.from_numpy(embeddings.astype(np.float32))).squeeze(-1)
            scores = np.asarray(torch.sigmoid(logits).numpy(), dtype=np.float64)
        distances = mahalanobis_distances(embeddings, self.ood_center, self.ood_inverse)
        return scores, distances

    def save(self, path: Path) -> dict[str, Any]:
        arrays = {key: value.detach().numpy() for key, value in self.model.state_dict().items()}
        arrays.update(
            {
                "preprocessing_center": self.center,
                "preprocessing_scale": self.scale,
                "ood_center": self.ood_center,
                "ood_inverse": self.ood_inverse,
            }
        )
        if any(not np.isfinite(value).all() for value in arrays.values()):
            raise ValueError("nonfinite model artifact")
        with path.open("xb") as stream:
            np.savez_compressed(stream, **arrays)
        # Safe numeric-only round trip verifies retained bytes, not just serialization.
        with np.load(path, allow_pickle=False) as saved:
            if set(saved.files) != set(arrays) or any(
                not np.array_equal(saved[key], value) for key, value in arrays.items()
            ):
                raise ValueError("model artifact round trip failed")
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


def benchmark(
    predictor: Predictor, records: Sequence[SequenceRecord], config: Mapping[str, Any]
) -> list[dict[str, Any]]:
    reports = []
    for size in config["batch_sizes"]:
        indices = np.random.default_rng(SEED).choice(
            len(records), size=size, replace=size > len(records)
        )
        batch = [records[int(i)] for i in indices]
        for _ in range(config["warmup_calls_per_batch_size"]):
            predictor.score(batch)
        timings = []
        for _ in range(config["measured_calls_per_batch_size"]):
            start = perf_counter()
            predictor.score(batch)
            timings.append(perf_counter() - start)
        measured = np.asarray(timings)
        reports.append(
            {
                "batch_size": size,
                "warmup_calls": config["warmup_calls_per_batch_size"],
                "measured_calls": len(timings),
                "scope": config["inference_scope"],
                "batch_selection": "seeded_uniform_test_rows_without_replacement_unless_short",
                "batch_record_content_sha256": canonical_digest(batch),
                "batch_family_counts": dict(Counter(r["family"] for r in batch)),
                "batch_latency_ms": quantiles(measured * 1000),
                "throughput_flows_per_second": size * len(timings) / float(measured.sum()),
                "not_durable_pipeline_throughput": True,
            }
        )
    return reports


def make_partitions(
    records: Sequence[SequenceRecord],
    config: Mapping[str, Any],
    family: str,
    orientation: Mapping[str, str],
) -> dict[str, list[SequenceRecord]]:
    fit = select_fit(
        [r for r in records if r["family"] != family],
        scenarios=set(config["splits"]["fit_source_scenarios"]),
        allowed_families=None,
        per_class_cap=config["model"]["fit_per_binary_class_cap"],
        seed=config["execution"]["seed"],
    )
    held_scenarios = config["splits"]["held_family_attack_scenarios"][family]
    partitions = {
        "fit": fit,
        "site_calibration": [r for r in records if r["scenario"] == orientation["calibration"]],
        "benign_test": [r for r in records if r["scenario"] == orientation["benign_test"]],
        "held_attack": [
            r for r in records if r["family"] == family and r["scenario"] in held_scenarios
        ],
    }
    assert_strict_family_rotation(held_family=family, **partitions)
    return partitions


def run_rotation(
    records: Sequence[SequenceRecord],
    config: Mapping[str, Any],
    family: str,
    orientation: Mapping[str, str],
    output: Path,
    name: str,
) -> dict[str, Any]:
    partitions = make_partitions(records, config, family, orientation)
    datasets = {key: build_dataset(value) for key, value in partitions.items()}
    dataset = datasets["fit"]
    center, scale = fit_standardizer(dataset.aggregate)
    validate_model_inputs(datasets, center, scale)
    memory = MemorySampler()
    memory.thread.start()
    try:
        start = perf_counter()
        torch.manual_seed(config["execution"]["seed"])
        model = FusionNet(
            max_length=20,
            features_per_packet=4,
            aggregate_dim=24,
            encoder=config["model"]["encoder"],
            embedding_dim=config["model"]["sequence_embedding_dim"],
        )
        torch_fit(
            model,
            dataset,
            use_aggregate=True,
            center=center,
            scale=scale,
            epochs=config["model"]["epochs"],
        )
        predictor = Predictor(model, center, scale, np.empty(0), np.empty(0))
        benign_embeddings = predictor.embeddings(dataset)[dataset.binary_label == 0]
        predictor.ood_center, predictor.ood_inverse = mahalanobis_fit(benign_embeddings)
        fit_seconds = perf_counter() - start
        site_scores, site_distances = predictor.score(partitions["site_calibration"])
        cuts = {
            f"{channel}_{tier}": threshold_for_fpr(values, config["calibration"][budget])
            for channel, values in (("known", site_scores), ("ood", site_distances))
            for tier, budget in (
                ("direct", "direct_fpr_budget_per_channel"),
                ("review", "review_inclusive_budget_per_channel"),
            )
        }
        site = evaluate_scores(
            site_scores,
            site_distances,
            datasets["site_calibration"].binary_label,
            cuts,
            calibration_distances=site_distances,
        )
        if (
            site["benign"]["direct_union_fpr"]["rate"]
            > config["calibration"]["direct_union_budget"]
            or site["benign"]["review_inclusive_rate"]["rate"]
            > config["calibration"]["review_inclusive_union_budget"]
        ):
            raise ValueError("empirical calibration union budget violated")
        test_records = partitions["held_attack"] + partitions["benign_test"]
        scores, distances = predictor.score(test_records)
        labels = np.concatenate(
            (datasets["held_attack"].binary_label, datasets["benign_test"].binary_label)
        )
        metrics = evaluate_scores(
            scores, distances, labels, cuts, calibration_distances=site_distances
        )
        cost = benchmark(predictor, test_records, config["measurement"])
        artifact = predictor.save(output / f"{name}.npz")
    finally:
        memory_report = memory.finish()
    return {
        "rotation": name,
        "held_family": family,
        "site_orientation": dict(orientation),
        "partition_provenance": {
            key: partition_provenance(value) for key, value in partitions.items()
        },
        "held_attack_observability": dict(
            Counter(r["observability"] for r in partitions["held_attack"])
        ),
        "thresholds": cuts,
        "calibration": site,
        "test": metrics,
        "fit_wall_seconds": fit_seconds,
        "inference": cost,
        "memory": memory_report,
        "artifact": artifact,
    }


def run(manifest: Path, pcaps: Path, output: Path) -> Path:
    if output.exists():
        raise FileExistsError("refusing to overwrite registered experiment evidence")
    commit = clean_execution_commit(ROOT)
    config = load_registration(ROOT)
    if text_digest(manifest) != config["prepared_manifest"]["sha256"]:
        raise ValueError("local preparation manifest differs from registration")
    verify_capture_pool(ROOT, pcaps)
    raw = load_verified_preparation(ROOT, manifest)
    records = deduplicate_records(raw)
    if (len(raw), len(records)) != (
        config["prepared_manifest"]["expected_rows"],
        config["prepared_manifest"]["expected_unique_model_inputs"],
    ):
        raise ValueError("prepared/deduplicated record counts differ from registration")
    torch.set_num_threads(config["execution"]["torch_threads"])
    output.mkdir(parents=True, exist_ok=False)
    start = perf_counter()
    started_at = datetime.now(UTC).isoformat()
    results = []
    for family in config["splits"]["held_family_attack_scenarios"]:
        for index, orientation in enumerate(config["splits"]["site_orientations"], start=1):
            name = f"{family}_site_{index}"
            print(f"running {name}", flush=True)
            result = run_rotation(records, config, family, orientation, output, name)
            write_new_json(output / f"{name}.json", result)
            results.append(result)
            print(
                f"completed {name}: {result['test']['attack']['rows']} attacks, "
                f"unknown={result['test']['attack']['direct_suspicious_unknown']['rate']:.5f}, "
                f"benign_FPR={result['test']['benign']['direct_union_fpr']['rate']:.5f}",
                flush=True,
            )
    if len(results) != config["splits"]["expected_rotations"]:
        raise ValueError("incomplete registered rotation matrix")
    for family in config["splits"]["held_family_attack_scenarios"]:
        hashes = {r["artifact"]["sha256"] for r in results if r["held_family"] == family}
        if len(hashes) != 1:
            raise ValueError("seeded model artifacts differ across site rotations")
    verify_capture_pool(ROOT, pcaps)
    final = load_verified_preparation(ROOT, manifest)
    if (
        canonical_digest(final) != canonical_digest(raw)
        or load_registration(ROOT) != config
        or clean_execution_commit(ROOT) != commit
    ):
        raise ValueError("code or data changed during experiment")
    report_path = output / "report.json"
    write_new_json(
        report_path,
        {
            "schema_version": "1.0.0",
            "experiment_id": config["experiment_id"],
            "execution_status": "completed",
            "scientific_status": "development_only_not_candidate_selected",
            "code_commit": commit,
            "registration_sha256_utf8_lf": REGISTRATION_SHA256,
            "registration": config,
            "preparation_manifest": read_object(manifest),
            "started_at": started_at,
            "completed_at": datetime.now(UTC).isoformat(),
            "elapsed_seconds": perf_counter() - start,
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
            "rotations": results,
            "limitations": [
                "Whole-label-family exclusion is not whole-malware-environment exclusion.",
                "Public benign research labels do not constitute deployed operator approval.",
                "No signature or temporal-context channel participates in this experiment.",
                "Model-stage CPU latency is not durable-pipeline throughput.",
                "Wilson intervals assume independent Bernoulli rows; capture correlation remains.",
                "No usable chronological timestamps: false alerts/hour unavailable.",
                "Small deduplicated attack families and two benign devices limit generalization.",
                "No frozen data evaluated and no candidate selected or promoted.",
            ],
        },
    )
    return report_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared-manifest", required=True, type=Path)
    parser.add_argument("--pcap-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    print(run(args.prepared_manifest, args.pcap_dir, args.output_dir), flush=True)


if __name__ == "__main__":
    main()
