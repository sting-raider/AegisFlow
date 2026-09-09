"""Execute immutable DEV2-CONTEXT-001 development evidence, never final tests."""

from __future__ import annotations

import argparse
import importlib
import importlib.metadata
import platform
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Any

from training.v2.context_analysis import matrix_choices, paired_analysis
from training.v2.context_model import load_context_predictor
from training.v2.context_runner import CaseExecution, run_case
from training.v2.provenance import (
    canonical_digest,
    clean_execution_commit,
    load_verified_preparation,
    read_object,
    write_new_json,
)
from training.v2.registered_context import (
    REGISTRATION_SHA256,
    load_context_rows,
    load_registration,
)
from training.v2.registered_family import text_digest
from training.v2.registered_missingness import admit_cohort
from training.v2.transfer_support import transfer_partitions

ROOT = Path(__file__).resolve().parents[2]


def verify_artifacts(
    output: Path, reports: list[dict[str, Any]], config: dict[str, Any]
) -> int:
    declared: set[str] = set()
    for report in reports:
        if report["status"] != "evaluated":
            if "artifact" in report:
                raise ValueError("ineligible context case claims an artifact")
            continue
        metadata = report["artifact"]
        path = output / metadata["file"]
        if path.name in declared or path.resolve().parent != output.resolve():
            raise ValueError("duplicate or escaping context artifact")
        load_context_predictor(path, metadata, config, view=report["view"])
        declared.add(path.name)
    if {path.name for path in output.glob("*.npz")} != declared:
        raise ValueError("unbound context model artifact")
    return len(declared)


def run(
    prepared_manifest: Path, sidecar_directory: Path, output: Path
) -> Path:
    if output.exists():
        raise FileExistsError("refusing to reuse context experiment evidence")
    commit = clean_execution_commit(ROOT)
    config = load_registration(ROOT)
    if text_digest(prepared_manifest) != config["prepared_manifest"]["sha256"]:
        raise ValueError("local preparation manifest differs from context registration")
    context_manifest = read_object(ROOT / config["context_manifest"]["path"])
    raw = load_verified_preparation(ROOT, prepared_manifest)
    context_rows = load_context_rows(sidecar_directory, context_manifest)
    started, started_at = perf_counter(), datetime.now(UTC).isoformat()
    cohort, cohort_report = admit_cohort(raw, config)
    cohort_seconds = perf_counter() - started
    if set(context_rows) != {row["event_id"] for row in raw}:
        raise ValueError("registered context sidecars differ from prepared rows")

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
    executions: list[CaseExecution] = []
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
                case_id = f"choice{choice:02d}-{view}"
                print(
                    f"running {len(executions) + 1}/"
                    f"{config['splits']['expected_model_fits']} {case_id}",
                    flush=True,
                )
                execution = run_case(
                    partitions,
                    context_rows,
                    config,
                    case_id=case_id,
                    target=target,
                    sources=sources,
                    view=view,
                    output=output,
                )
                write_new_json(output / f"{case_id}.json", execution.report)
                executions.append(execution)
                print(
                    f"completed {case_id}: {execution.report['status']}", flush=True
                )
        if any(item["num_threads"] != 1 for item in pools.threadpool_info()):
            raise ValueError("registered numerical thread limits changed during execution")
        reports = [execution.report for execution in executions]
        artifacts = verify_artifacts(output, reports, config)

    if (
        len(executions) != config["splits"]["expected_model_fits"]
        or sum(len(report["site_evaluations"]) for report in reports)
        != config["splits"]["expected_site_evaluations"]
    ):
        raise ValueError("context study matrix is incomplete")
    comparisons = paired_analysis(executions, config)

    final_rows = load_verified_preparation(ROOT, prepared_manifest)
    load_context_rows(sidecar_directory, context_manifest)
    if (
        canonical_digest(final_rows) != canonical_digest(raw)
        or load_registration(ROOT) != config
        or clean_execution_commit(ROOT) != commit
    ):
        raise ValueError("context code, inputs, or registration changed during execution")
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
            "context_manifest": context_manifest,
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
                    for name in (
                        "numpy",
                        "scikit-learn",
                        "scipy",
                        "threadpoolctl",
                        "psutil",
                    )
                },
            },
            "coverage": {
                "planned_model_entries": len(reports),
                "linear_fit_attempts": sum(report["fit_attempted"] for report in reports),
                "evaluated_models": artifacts,
                "evaluated_site_entries": sum(
                    site["status"] == "evaluated"
                    for report in reports
                    for site in report["site_evaluations"]
                ),
                "planned_site_entries": config["splits"]["expected_site_evaluations"],
            },
            "cases": reports,
            "paired_analysis": comparisons,
            "limitations": [
                *cohort_report["limitations"],
                "Whole-capture five-tuple merging prevents within-flow chronology recovery.",
                (
                    "The terminal reference deliberately uses future information and "
                    "is not deployable."
                ),
                "Mahalanobis operates on standardized inputs, not a learned embedding.",
                "Paired intervals are descriptive because captures and fit choices are correlated.",
                "Public benign research labels are not deployed operator approval.",
                "No signatures, packet sequence, frozen evaluation, or model selection is used.",
                "Model-stage latency is not durable streaming service throughput.",
            ],
        },
    )
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared-manifest", required=True, type=Path)
    parser.add_argument("--context-sidecar-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    print(
        run(args.prepared_manifest, args.context_sidecar_dir, args.output_dir),
        flush=True,
    )


if __name__ == "__main__":
    main()
