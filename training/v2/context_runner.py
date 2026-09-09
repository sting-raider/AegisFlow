"""Case execution primitives for the immutable DEV2-CONTEXT-001 study."""

from __future__ import annotations

import hashlib
import warnings
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter
from typing import Any

import numpy as np
from sklearn.exceptions import ConvergenceWarning

from training.v2.calibration import threshold_for_fpr
from training.v2.context_model import (
    ContextPredictor,
    fit_context_predictor,
    load_context_predictor,
)
from training.v2.origin_probe import IneligibleProbe, vector_keys
from training.v2.provenance import canonical_digest, partition_provenance
from training.v2.registered_context import ContextRow, context_views
from training.v2.registered_family import (
    VERDICTS,
    MemorySampler,
    evaluate_scores,
    quantiles,
    verdicts,
)
from training.v2.registered_missingness import assert_transformed_disjoint
from training.v2.tensors import SequenceRecord


@dataclass(frozen=True)
class PairedSignals:
    target_event_ids: tuple[str, ...]
    benign_event_ids: tuple[str, ...]
    target_attack_direct: np.ndarray
    target_attack_or_review: np.ndarray
    independent_benign_direct: np.ndarray


@dataclass(frozen=True)
class CaseExecution:
    report: dict[str, Any]
    paired_signals: tuple[PairedSignals, ...]


def matrix_provenance(matrix: np.ndarray) -> dict[str, Any]:
    values = np.asarray(matrix, dtype=np.float64)
    return {
        "rows": len(values),
        "dimension": values.shape[1],
        "distinct_inputs": len(set(vector_keys(values))),
        "float64_le_sha256": hashlib.sha256(b"".join(vector_keys(values))).hexdigest(),
    }


def _labels(records: Sequence[SequenceRecord]) -> np.ndarray:
    labels = np.asarray(
        [int(record["binary_label"] == "malicious") for record in records],
        dtype=np.int64,
    )
    if not np.isin(labels, [0, 1]).all():
        raise ValueError("invalid binary labels")
    return labels


def benchmark_matrix(
    predictor: ContextPredictor,
    matrix: np.ndarray,
    records: Sequence[SequenceRecord],
    config: Mapping[str, Any],
) -> list[dict[str, Any]]:
    measurement = config["measurement"]
    results = []
    for size in measurement["batch_sizes"]:
        indices = np.random.default_rng(config["execution"]["seed"]).choice(
            len(records), size, replace=size > len(records)
        )
        batch = matrix[indices]
        selected = [records[int(index)] for index in indices]
        for _ in range(measurement["warmup_calls_per_batch_size"]):
            predictor.score_matrix(batch)
        timings = []
        for _ in range(measurement["measured_calls_per_batch_size"]):
            started = perf_counter()
            predictor.score_matrix(batch)
            timings.append(perf_counter() - started)
        measured = np.asarray(timings)
        results.append(
            {
                "batch_size": size,
                "warmup_calls": measurement["warmup_calls_per_batch_size"],
                "measured_calls": len(timings),
                "scope": measurement["inference_scope"],
                "batch_record_content_sha256": canonical_digest(selected),
                "batch_family_counts": dict(Counter(row["family"] for row in selected)),
                "batch_latency_ms": quantiles(measured * 1000),
                "throughput_flows_per_second": (
                    size * len(timings) / float(measured.sum())
                ),
                "not_durable_pipeline_throughput": True,
            }
        )
    return results


def evaluate_site(
    predictor: ContextPredictor,
    matrices: Mapping[str, np.ndarray],
    partitions: Mapping[str, list[SequenceRecord]],
    orientation: Mapping[str, str],
    config: Mapping[str, Any],
) -> tuple[dict[str, Any], PairedSignals]:
    scores = {
        role: predictor.score_matrix(matrices[role])
        for role in ("site_calibration", "benign_test", "target")
    }
    labels = {
        role: _labels(partitions[role])
        for role in ("site_calibration", "benign_test", "target")
    }
    cal_scores, cal_distances = scores["site_calibration"]
    cuts = {
        f"{channel}_{tier}": threshold_for_fpr(values, config["calibration"][budget])
        for channel, values in (("known", cal_scores), ("ood", cal_distances))
        for tier, budget in (
            ("direct", "direct_fpr_budget_per_channel"),
            ("review", "review_inclusive_budget_per_channel"),
        )
    }
    metrics = {
        role: evaluate_scores(
            *scores[role], labels[role], cuts, calibration_distances=cal_distances
        )
        for role in scores
    }
    calibration = metrics["site_calibration"]["benign"]
    if (
        calibration["direct_union_fpr"]["rate"]
        > config["calibration"]["direct_union_budget"]
        or calibration["review_inclusive_rate"]["rate"]
        > config["calibration"]["review_inclusive_union_budget"]
    ):
        raise ValueError("registered empirical calibration budget violated")

    combined_scores = np.concatenate((scores["target"][0], scores["benign_test"][0]))
    combined_distances = np.concatenate(
        (scores["target"][1], scores["benign_test"][1])
    )
    combined_labels = np.concatenate((labels["target"], labels["benign_test"]))
    combined = evaluate_scores(
        combined_scores,
        combined_distances,
        combined_labels,
        cuts,
        calibration_distances=cal_distances,
    )
    families = np.asarray([row["family"] for row in partitions["target"]])
    fit_families = {row["family"] for row in partitions["fit"]}
    family_metrics = {}
    for family in sorted(set(families) - {"benign"}):
        mask = families == family
        family_metrics[str(family)] = {
            "present_in_supervised_fit": family in fit_families,
            "metrics": evaluate_scores(
                scores["target"][0][mask],
                scores["target"][1][mask],
                labels["target"][mask],
                cuts,
                calibration_distances=cal_distances,
            ),
        }
    target_verdicts = verdicts(*scores["target"], cuts)
    benign_verdicts = verdicts(*scores["benign_test"], cuts)
    attack_mask = labels["target"] == 1
    direct_names = ("known_attack", "suspicious_unknown")
    signals = PairedSignals(
        target_event_ids=tuple(
            row["event_id"]
            for row, attack in zip(partitions["target"], attack_mask, strict=True)
            if attack
        ),
        benign_event_ids=tuple(row["event_id"] for row in partitions["benign_test"]),
        target_attack_direct=np.isin(target_verdicts[attack_mask], direct_names),
        target_attack_or_review=target_verdicts[attack_mask] != "benign",
        independent_benign_direct=np.isin(benign_verdicts, direct_names),
    )
    combined_verdict_counts = combined
    report = {
        "status": "evaluated",
        "orientation": dict(orientation),
        "thresholds": cuts,
        "partition_provenance": {
            role: partition_provenance(rows) for role, rows in partitions.items()
        },
        "input_provenance": {
            role: matrix_provenance(matrices[role])
            for role in ("site_calibration", "benign_test", "target")
        },
        "calibration": metrics["site_calibration"],
        "target": metrics["target"],
        "independent_benign": metrics["benign_test"],
        "combined": combined_verdict_counts,
        "confusion_truth_order": ["benign", "attack"],
        "confusion_verdict_order": list(VERDICTS),
        "confusion_matrix": [
            [combined[truth]["four_verdict_counts"][verdict] for verdict in VERDICTS]
            for truth in ("benign", "attack")
        ],
        "target_families": family_metrics,
        "inference": benchmark_matrix(
            predictor,
            np.concatenate((matrices["target"], matrices["benign_test"])),
            partitions["target"] + partitions["benign_test"],
            config,
        ),
    }
    return report, signals


def run_case(
    partitions: dict[str, list[SequenceRecord]],
    context_rows: Mapping[str, ContextRow],
    config: Mapping[str, Any],
    *,
    case_id: str,
    target: str,
    sources: list[str],
    view: str,
    output: Path,
) -> CaseExecution:
    started = perf_counter()
    sampler = MemorySampler()
    sampler.thread.start()
    entry: dict[str, Any] = {
        "case_id": case_id,
        "target_capture": target,
        "fit_sources": sources,
        "view": view,
        "fit_attempted": False,
        "partition_provenance": {
            role: partition_provenance(rows) for role, rows in partitions.items()
        },
    }
    phase = "input_construction"
    paired: list[PairedSignals] = []
    fit_started = started
    try:
        all_views = {
            role: context_views(
                rows,
                context_rows,
                role=role,
                seed=config["execution"]["seed"],
            )
            for role, rows in partitions.items()
        }
        raw_matrices = {role: views[view] for role, views in all_views.items()}
        entry["feature_build_seconds"] = perf_counter() - started
        entry["raw_inputs"] = {
            role: matrix_provenance(matrix) for role, matrix in raw_matrices.items()
        }
        phase, fit_started = "linear_and_ood_fit", perf_counter()
        labels = _labels(partitions["fit"])
        entry["fit_attempted"] = True
        with warnings.catch_warnings():
            warnings.simplefilter("error", ConvergenceWarning)
            predictor = fit_context_predictor(raw_matrices["fit"], labels, config)
        transformed = {
            role: predictor.transform.transform(matrix)
            for role, matrix in raw_matrices.items()
        }
        assert_transformed_disjoint(transformed)
        entry["transformed_inputs"] = {
            role: matrix_provenance(matrix) for role, matrix in transformed.items()
        }
        entry["fit_seconds"] = perf_counter() - fit_started
        phase = "site_evaluation"
        sites = []
        verified_matrices = dict(raw_matrices)
        for index, orientation in enumerate(config["splits"]["site_orientations"]):
            roles = dict(partitions)
            matrices = dict(raw_matrices)
            if index == 1:
                roles["site_calibration"], roles["benign_test"] = (
                    roles["benign_test"],
                    roles["site_calibration"],
                )
                for role in ("site_calibration", "benign_test"):
                    matrices[role] = context_views(
                        roles[role],
                        context_rows,
                        role=role,
                        seed=config["execution"]["seed"],
                    )[view]
            site, signals = evaluate_site(predictor, matrices, roles, orientation, config)
            sites.append(site)
            paired.append(signals)
            verified_matrices.update(
                {f"orientation_{index}_{role}": matrices[role] for role in matrices}
            )
        phase = "artifact_roundtrip"
        metadata = predictor.save(output / f"{case_id}.npz", view=view)
        restored = load_context_predictor(
            output / metadata["file"], metadata, config, view=view
        )
        for matrix in verified_matrices.values():
            if not all(
                np.array_equal(left, right)
                for left, right in zip(
                    predictor.score_matrix(matrix),
                    restored.score_matrix(matrix),
                    strict=True,
                )
            ):
                raise ValueError("restored context model changes inference")
        entry.update(
            {"status": "evaluated", "site_evaluations": sites, "artifact": metadata}
        )
    except (
        IneligibleProbe,
        ConvergenceWarning,
        np.linalg.LinAlgError,
        FloatingPointError,
    ) as error:
        if phase in {"site_evaluation", "artifact_roundtrip"}:
            raise
        entry.setdefault("fit_seconds", perf_counter() - fit_started)
        entry.update(
            {
                "status": "ineligible",
                "failure_phase": phase,
                "reason": str(error),
                "failure_type": type(error).__name__,
                "site_evaluations": [
                    {
                        "status": "ineligible_model",
                        "orientation": dict(orientation),
                        "reason": str(error),
                    }
                    for orientation in config["splits"]["site_orientations"]
                ],
            }
        )
        paired.clear()
    finally:
        entry["memory"] = sampler.finish()
    entry["model_wall_seconds"] = perf_counter() - started
    return CaseExecution(entry, tuple(paired))
