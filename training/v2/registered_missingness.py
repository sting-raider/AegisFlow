"""Execute the immutable DEV2-MISSINGNESS-001 development matrix, never final tests."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.metadata
import platform
import warnings
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from itertools import combinations
from pathlib import Path
from time import perf_counter
from typing import Any

import numpy as np
from sklearn.exceptions import ConvergenceWarning
from sklearn.linear_model import LogisticRegression

from training.v2.calibration import threshold_for_fpr
from training.v2.missingness import MissingnessTransform, observation_inputs
from training.v2.missingness_model import (
    MissingnessPredictor,
    benchmark,
    load_predictor,
    model_kwargs,
)
from training.v2.origin_probe import IneligibleProbe, vector_keys
from training.v2.provenance import (
    canonical_digest,
    clean_execution_commit,
    load_verified_preparation,
    partition_provenance,
    read_object,
    verify_capture_pool,
    write_new_json,
)
from training.v2.registered_family import VERDICTS, MemorySampler, evaluate_scores, text_digest
from training.v2.tensors import SequenceRecord
from training.v2.transfer_support import (
    REGISTRATION_SHA256,
    common_support,
    load_registration,
    transfer_partitions,
)

ROOT = Path(__file__).resolve().parents[2]


def admit_cohort(
    records: Sequence[SequenceRecord],
    config: Mapping[str, Any],
) -> tuple[list[SequenceRecord], dict[str, Any]]:
    cohort, report = common_support(records)
    expected = config["cohort"]
    checks = {
        "core_groups": report["input_core_groups"],
        "cross_capture_groups": report["cross_capture_groups"],
        "groups_with_optional_packet_variants": report["groups_with_optional_packet_variants"],
        "cross_capture_excluded_rows": report["cross_capture_excluded"]["rows"],
        "within_capture_ambiguous_excluded_rows": report["within_capture_ambiguous_excluded"][
            "rows"
        ],
        "within_capture_duplicate_rows": report["within_capture_duplicate_rows"]["rows"],
        "retained_rows": len(cohort),
        "retained_event_ids_sha256": report["retained"]["event_ids_sha256"],
        "retained_records_sha256": report["retained"]["records_sha256"],
    }
    if len(records) != config["prepared_manifest"]["expected_rows"] or any(
        value != expected[key] for key, value in checks.items()
    ):
        raise ValueError("common-support cohort differs from registration")
    return cohort, report


def matrix_choices(config: Mapping[str, Any]) -> list[tuple[str, list[str]]]:
    environments = config["splits"]["attack_environments"]
    choices: list[tuple[str, list[str]]] = []
    for target in environments:
        other = [source for source in environments if source != target]
        choices.extend((target, sources) for sources in ([other[0]], [other[1]], other))
    if len(choices) != config["splits"]["expected_source_target_choices"]:
        raise ValueError("unexpected source/target matrix size")
    return choices


def transformed_provenance(matrices: Mapping[str, np.ndarray]) -> dict[str, Any]:
    return {
        role: {
            "rows": len(values),
            "dimension": values.shape[1],
            "distinct_inputs": len(set(vector_keys(values))),
            "float64_le_sha256": hashlib.sha256(b"".join(vector_keys(values))).hexdigest(),
        }
        for role, values in matrices.items()
    }


def assert_transformed_disjoint(matrices: Mapping[str, np.ndarray]) -> None:
    keys = {role: set(vector_keys(values)) for role, values in matrices.items()}
    for left, right in combinations(keys, 2):
        overlap = keys[left] & keys[right]
        if overlap:
            raise IneligibleProbe(
                f"transformed inputs alias across {left}/{right}: {len(overlap)} distinct vectors"
            )


def site_metrics(
    predictor: MissingnessPredictor,
    partitions: Mapping[str, list[SequenceRecord]],
    orientation: Mapping[str, str],
    config: Mapping[str, Any],
) -> dict[str, Any]:
    scores = {
        role: predictor.score(records) for role, records in partitions.items() if role != "fit"
    }
    labels = {
        role: np.asarray([int(r["binary_label"] == "malicious") for r in records])
        for role, records in partitions.items()
        if role != "fit"
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
    cal = metrics["site_calibration"]["benign"]
    if (
        cal["direct_union_fpr"]["rate"] > config["calibration"]["direct_union_budget"]
        or cal["review_inclusive_rate"]["rate"]
        > config["calibration"]["review_inclusive_union_budget"]
    ):
        raise ValueError("registered empirical calibration budget violated")
    combined_scores = np.concatenate((scores["target"][0], scores["benign_test"][0]))
    combined_distances = np.concatenate((scores["target"][1], scores["benign_test"][1]))
    combined_labels = np.concatenate((labels["target"], labels["benign_test"]))
    combined = evaluate_scores(
        combined_scores,
        combined_distances,
        combined_labels,
        cuts,
        calibration_distances=cal_distances,
    )
    families = np.asarray([r["family"] for r in partitions["target"]])
    fit_families = {r["family"] for r in partitions["fit"]}
    family_metrics = {}
    for family in sorted(set(families) - {"benign"}):
        mask = families == family
        family_metrics[str(family)] = {
            "present_in_supervised_fit": bool(family in fit_families),
            "metrics": evaluate_scores(
                scores["target"][0][mask],
                scores["target"][1][mask],
                labels["target"][mask],
                cuts,
                calibration_distances=cal_distances,
            ),
        }
    return {
        "status": "evaluated",
        "orientation": dict(orientation),
        "thresholds": cuts,
        "partition_provenance": {
            role: partition_provenance(rows) for role, rows in partitions.items()
        },
        "calibration": metrics["site_calibration"],
        "target": metrics["target"],
        "independent_benign": metrics["benign_test"],
        "combined": combined,
        "confusion_truth_order": ["benign", "attack"],
        "confusion_verdict_order": list(VERDICTS),
        "confusion_matrix": [
            [combined[truth]["four_verdict_counts"][verdict] for verdict in VERDICTS]
            for truth in ("benign", "attack")
        ],
        "target_families": family_metrics,
        "inference": benchmark(predictor, partitions["target"] + partitions["benign_test"], config),
    }


def run_case(
    partitions: dict[str, list[SequenceRecord]],
    config: Mapping[str, Any],
    *,
    case_id: str,
    target: str,
    sources: list[str],
    view: str,
    kind: str,
    output: Path,
) -> dict[str, Any]:
    started = perf_counter()
    sampler = MemorySampler()
    sampler.thread.start()
    entry: dict[str, Any] = {
        "case_id": case_id,
        "target_capture": target,
        "fit_sources": sources,
        "view": view,
        "transform": kind,
        "fit_attempted": False,
        "partition_provenance": {
            role: partition_provenance(rows) for role, rows in partitions.items()
        },
    }
    phase = "input_construction"
    fit_started = started
    try:
        inputs = {role: observation_inputs(rows) for role, rows in partitions.items()}
        entry["feature_build_seconds"] = perf_counter() - started
        entry["observation_support"] = {role: batch.support() for role, batch in inputs.items()}
        phase, fit_started = "preprocessing", perf_counter()
        transform = MissingnessTransform(view, kind, seed=config["execution"]["seed"])
        transform.fit(inputs["fit"])
        entry["feature_order"] = list(transform.feature_names)
        matrices = {role: transform.transform(batch) for role, batch in inputs.items()}
        entry["transformed_inputs"] = transformed_provenance(matrices)
        assert_transformed_disjoint(matrices)
        phase = "linear_fit"
        model = LogisticRegression(**model_kwargs(config))
        labels = np.asarray([int(row["binary_label"] == "malicious") for row in partitions["fit"]])
        if set(labels) != {0, 1}:
            raise ValueError("registered linear fitting requires both binary classes")
        entry["fit_attempted"] = True
        with warnings.catch_warnings():
            warnings.simplefilter("error", ConvergenceWarning)
            model.fit(matrices["fit"], labels)
        phase = "ood_fit"
        benign = matrices["fit"][labels == 0]
        if len(benign) < 2:
            raise ValueError("benign covariance fitting requires at least two rows")
        center = benign.mean(axis=0)
        covariance = np.cov(benign, rowvar=False)
        covariance += np.eye(covariance.shape[0]) * config["ood"]["covariance_ridge"]
        inverse = np.linalg.inv(covariance)
        if not np.isfinite(inverse).all():
            raise FloatingPointError("nonfinite fitted covariance inverse")
        predictor = MissingnessPredictor(transform, model, center, inverse)
        entry["fit_seconds"] = perf_counter() - fit_started
        phase = "site_evaluation"
        sites = []
        for index, orientation in enumerate(config["splits"]["site_orientations"]):
            roles = dict(partitions)
            if index == 1:
                roles["site_calibration"], roles["benign_test"] = (
                    roles["benign_test"],
                    roles["site_calibration"],
                )
            sites.append(site_metrics(predictor, roles, orientation, config))
        phase = "artifact_roundtrip"
        metadata = predictor.save(output / f"{case_id}.npz")
        restored = load_predictor(output / metadata["file"], metadata, config)
        for batch in inputs.values():
            if not all(
                np.array_equal(left, right)
                for left, right in zip(
                    predictor.score_inputs(batch),
                    restored.score_inputs(batch),
                    strict=True,
                )
            ):
                raise ValueError("restored numeric model changes inference")
        entry.update({"status": "evaluated", "site_evaluations": sites, "artifact": metadata})
    except (
        IneligibleProbe,
        ConvergenceWarning,
        np.linalg.LinAlgError,
        FloatingPointError,
    ) as error:
        # Expected scientific/numeric failures remain coverage loss, never successful zero scores.
        # Schema, provenance, programming and artifact-integrity errors remain fatal.
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
                    {"status": "ineligible_model", "orientation": orientation, "reason": str(error)}
                    for orientation in config["splits"]["site_orientations"]
                ],
            }
        )
    finally:
        entry["memory"] = sampler.finish()
    entry["model_wall_seconds"] = perf_counter() - started
    return entry


def paired_comparisons(
    results: Sequence[Mapping[str, Any]], config: Mapping[str, Any]
) -> list[Any]:
    comparisons = []
    for target in config["splits"]["attack_environments"]:
        for view in config["representation"]["views"]:
            for kind in config["representation"]["transforms"]:
                entries = [
                    r
                    for r in results
                    if (r["target_capture"], r["view"], r["transform"]) == (target, view, kind)
                ]
                if len(entries) != 3 or [len(r["fit_sources"]) for r in entries] != [1, 1, 2]:
                    raise ValueError(
                        "source-addition comparison lacks its registered three choices"
                    )
                for site in range(2):
                    comparison: dict[str, Any] = {
                        "target_capture": target,
                        "view": view,
                        "transform": kind,
                        "orientation": config["splits"]["site_orientations"][site],
                        "case_ids": [r["case_id"] for r in entries],
                    }
                    if any(r["status"] != "evaluated" for r in entries):
                        comparison.update(
                            {
                                "status": "unpaired_ineligible_entries",
                                "ineligible_case_ids": [
                                    r["case_id"] for r in entries if r["status"] != "evaluated"
                                ],
                            }
                        )
                    else:
                        sites = [r["site_evaluations"][site] for r in entries]
                        for role in ("target", "site_calibration", "benign_test"):
                            if (
                                len(
                                    {
                                        s["partition_provenance"][role]["records_sha256"]
                                        for s in sites
                                    }
                                )
                                != 1
                            ):
                                raise ValueError("source-addition evaluation rows are not paired")

                        def values(item: Mapping[str, Any]) -> dict[str, float]:
                            attack, benign = (
                                item["target"]["attack"],
                                item["independent_benign"]["benign"],
                            )
                            return {
                                "target_attack_direct": attack["direct_detection"]["rate"],
                                "target_attack_unknown": attack["direct_suspicious_unknown"][
                                    "rate"
                                ],
                                "target_attack_or_review": attack["detection_or_review"]["rate"],
                                "independent_benign_fpr": benign["direct_union_fpr"]["rate"],
                                "independent_benign_review": benign["review_inclusive_rate"][
                                    "rate"
                                ],
                            }

                        combined = values(sites[2])
                        comparison.update(
                            {
                                "status": "paired",
                                "combined": combined,
                                "single_sources": [values(sites[0]), values(sites[1])],
                                "combined_minus_single": [
                                    {key: combined[key] - value for key, value in values(s).items()}
                                    for s in sites[:2]
                                ],
                            }
                        )
                    comparisons.append(comparison)
    return comparisons


def verify_artifacts(
    output: Path, results: Sequence[Mapping[str, Any]], config: Mapping[str, Any]
) -> int:
    declared = set()
    for result in results:
        if result["status"] != "evaluated":
            if "artifact" in result:
                raise ValueError("ineligible case claims an accepted model artifact")
            continue
        metadata = result["artifact"]
        path = output / metadata["file"]
        if path.name in declared or path.resolve().parent != output.resolve():
            raise ValueError("duplicate or escaping missingness artifact")
        restored = load_predictor(path, metadata, config)
        if (restored.transform.view, restored.transform.kind) != (
            result["view"],
            result["transform"],
        ):
            raise ValueError("artifact representation does not match its case")
        declared.add(path.name)
    if {p.name for p in output.glob("*.npz")} != declared:
        raise ValueError("unbound missingness model artifact")
    return len(declared)


def run(prepared_manifest: Path, pcaps: Path, output: Path) -> Path:
    if output.exists():
        raise FileExistsError("refusing to reuse missingness experiment evidence")
    commit = clean_execution_commit(ROOT)
    config = load_registration(ROOT)
    if text_digest(prepared_manifest) != config["prepared_manifest"]["sha256"]:
        raise ValueError("local preparation manifest differs from registration")
    verify_capture_pool(ROOT, pcaps)
    raw = load_verified_preparation(ROOT, prepared_manifest)
    started, started_at = perf_counter(), datetime.now(UTC).isoformat()
    cohort, cohort_report = admit_cohort(raw, config)
    cohort_seconds = perf_counter() - started
    output.mkdir(parents=True, exist_ok=False)
    write_new_json(
        output / "attempt.json",
        {
            "experiment_id": config["experiment_id"],
            "code_commit": commit,
            "registration_sha256_utf8_lf": REGISTRATION_SHA256,
            "started_at": started_at,
            "status": "attempt_started_not_completion_evidence",
        },
    )
    pools = importlib.import_module("threadpoolctl")
    results: list[dict[str, Any]] = []
    with pools.threadpool_limits(limits=config["execution"]["numerical_threads"]):
        environment_pools = [
            {
                key: item.get(key)
                for key in ("user_api", "internal_api", "prefix", "version", "num_threads")
            }
            for item in pools.threadpool_info()
        ]
        if any(item["num_threads"] != 1 for item in environment_pools):
            raise ValueError("registered numerical thread limit was not established")
        for choice, (target, sources) in enumerate(matrix_choices(config), start=1):
            partitions = transfer_partitions(
                cohort,
                sources=sources,
                target=target,
                background_benign=config["splits"]["background_benign"],
                orientation=config["splits"]["site_orientations"][0],
                per_class_cap=config["splits"]["fit_per_binary_class_cap"],
                seed=config["execution"]["seed"],
            )
            for view in config["representation"]["views"]:
                for kind in config["representation"]["transforms"]:
                    case_id = f"choice{choice:02d}-{view}-{kind}"
                    print(
                        f"running {len(results) + 1}/{config['splits']['expected_model_fits']} "
                        f"{case_id}",
                        flush=True,
                    )
                    result = run_case(
                        partitions,
                        config,
                        case_id=case_id,
                        target=target,
                        sources=sources,
                        view=view,
                        kind=kind,
                        output=output,
                    )
                    write_new_json(output / f"{case_id}.json", result)
                    results.append(result)
                    print(f"completed {case_id}: {result['status']}", flush=True)
        if any(item["num_threads"] != 1 for item in pools.threadpool_info()):
            raise ValueError("numerical thread limits changed during execution")
        artifacts = verify_artifacts(output, results, config)
    if (
        len(results) != config["splits"]["expected_model_fits"]
        or sum(len(r["site_evaluations"]) for r in results)
        != config["splits"]["expected_site_evaluations"]
    ):
        raise ValueError("missingness study matrix is incomplete")
    comparisons = paired_comparisons(results, config)
    verify_capture_pool(ROOT, pcaps)
    final = load_verified_preparation(ROOT, prepared_manifest)
    if (
        canonical_digest(final) != canonical_digest(raw)
        or load_registration(ROOT) != config
        or clean_execution_commit(ROOT) != commit
    ):
        raise ValueError("missingness code, inputs or configuration changed during execution")
    path = output / "report.json"
    write_new_json(
        path,
        {
            "schema_version": "1.0.0",
            "experiment_id": config["experiment_id"],
            "execution_status": "completed",
            "scientific_status": "development_only_no_candidate_selected",
            "code_commit": commit,
            "registration": config,
            "registration_sha256_utf8_lf": REGISTRATION_SHA256,
            "preparation_manifest": read_object(prepared_manifest),
            "cohort": cohort_report,
            "cohort_construction_seconds": cohort_seconds,
            "started_at": started_at,
            "completed_at": datetime.now(UTC).isoformat(),
            "elapsed_seconds": perf_counter() - started,
            "environment": {
                "python": platform.python_version(),
                "platform": platform.system(),
                "machine": platform.machine(),
                "numerical_pools": environment_pools,
                "dependencies": {
                    name: importlib.metadata.version(name)
                    for name in ("numpy", "scikit-learn", "scipy", "threadpoolctl", "psutil")
                },
            },
            "coverage": {
                "planned_model_entries": len(results),
                "linear_fit_attempts": sum(r["fit_attempted"] for r in results),
                "evaluated_models": artifacts,
                "evaluated_site_entries": sum(
                    s["status"] == "evaluated" for r in results for s in r["site_evaluations"]
                ),
                "planned_site_entries": config["splits"]["expected_site_evaluations"],
            },
            "cases": results,
            "source_addition_comparisons": comparisons,
            "limitations": [
                *cohort_report["limitations"],
                "Packet availability is not a study of unavailable vendor CSV fields.",
                "Mahalanobis operates on inputs, not a learned embedding.",
                "Tiny and correlated attack samples limit generalization.",
                "Site orientations share models and target rows, not independent repeats.",
                "Public benign research labels are not deployed operator approval.",
                "No signatures, host-context channel, frozen evaluation or model selection.",
                "Model-stage latency is not durable streaming service throughput.",
            ],
        },
    )
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared-manifest", required=True, type=Path)
    parser.add_argument("--pcap-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    print(run(args.prepared_manifest, args.pcap_dir, args.output_dir), flush=True)


if __name__ == "__main__":
    main()
