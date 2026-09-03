"""Validate retained ORIGIN-002 evidence without granting detector acceptance."""

from __future__ import annotations

import argparse
import math
import re
from pathlib import Path
from typing import Any

import numpy as np

from scripts.verify_registered_research_v2 import require, safe_aggregate
from training.v2.provenance import read_object
from training.v2.registered_origin import (
    REGISTRATION_SHA256,
    load_registration,
    text_digest,
    verify_probe_artifacts,
)

REPORT_PATH = "docs/research-v2/registered-results/DEV2-ORIGIN-002.json"
REPORT_SHA256 = "cb1d6916868dfa57c685c6d9ec87dd1f0ca8b58845fb03ec087db60a6ea1914c"
EXECUTION_COMMIT = "825efd123b711334e17e5fdc738a50281f8d8f95"
HISTORICAL_PATH = "docs/research-v2/registered-results/DEV2-ORIGIN-002-cost-incomplete.json"
HISTORICAL_SHA256 = "0f6f95b72f7b120c7f514a50b468112084df99bc2f63b664a24798067cc017c2"
SHA = re.compile(r"[0-9a-f]{64}")
DIMENSIONS = [24, 9, 100, 124, 21, 48, 48, 48]


def validate_report(root: Path, report: dict[str, Any]) -> None:
    try:
        safe_aggregate(report)
        config = load_registration(root)
        require(
            report["registration"] == config
            and report["registration_sha256_utf8_lf"] == REGISTRATION_SHA256,
            "origin registration mismatch",
        )
        require(report["code_commit"] == EXECUTION_COMMIT, "origin execution commit mismatch")
        require(
            report["execution_status"] == "completed"
            and report["scientific_status"] == "development_origin_diagnostic_only",
            "invalid origin evidence status",
        )
        require(
            report["preparation_manifest"] == read_object(root / config["preparation"]["path"]),
            "origin preparation binding mismatch",
        )
        require(
            report["encoder_report"]
            == {
                key: config["encoder_report"][key] for key in ("path", "sha256", "execution_commit")
            },
            "origin encoder report mismatch",
        )
        require(
            report["input_counts"]
            == dict(
                zip(config["input"]["scenarios"], config["input"]["expected_counts"], strict=True)
            ),
            "origin input counts changed",
        )
        require(
            report["origin_mapping"]
            == {str(i): name for i, name in enumerate(config["input"]["scenarios"])},
            "origin class mapping changed",
        )
        total = sum(config["input"]["expected_counts"])
        require(
            report["input_provenance"]["rows"] == total
            and report["input_provenance"]["binary_labels"] == {"benign": total},
            "origin input is not benign-only",
        )
        require(
            report["elapsed_seconds"] > 0
            and report["shared_tensor_build_seconds"] > 0
            and report["environment"]["torch_threads"] == 1,
            "missing origin measurements",
        )
        require(
            [view["view"] for view in report["views"]] == config["views"],
            "origin view matrix incomplete or reordered",
        )
        artifact_names: set[str] = set()
        for view, dimension in zip(report["views"], DIMENSIONS, strict=True):
            require(
                view["dimension"] == dimension
                and view["rows"] == total
                and SHA.fullmatch(view["features_sha256"]) is not None,
                "invalid origin feature binding",
            )
            grouping = view["grouping"]
            require(
                grouping["rows"] == total
                and 0 < grouping["groups"] <= total
                and grouping["duplicate_rows_beyond_first"] == total - grouping["groups"]
                and 0 <= grouping["cross_origin_ambiguous_groups"] <= grouping["groups"],
                "invalid origin group counts",
            )
            if view["status"] == "ineligible_grouped_folds":
                require(
                    bool(view["reason"]) and view["transforms"] == [],
                    "ineligible view fabricated scores",
                )
                continue
            require(
                view["status"] == "accounted_for"
                and [entry["transform"] for entry in view["transforms"]] == config["transforms"],
                "origin transform matrix incomplete",
            )
            for entry in view["transforms"]:
                require(
                    [fold["fold"] for fold in entry["folds"]] == list(range(1, 6)),
                    "origin folds missing or duplicated",
                )
                evaluated = []
                for fold in entry["folds"]:
                    parts = fold["partitions"]
                    require(
                        parts["train"]["rows"] + parts["test"]["rows"] == total,
                        "origin fold does not conserve input rows",
                    )
                    for role in ("train", "test"):
                        partition = parts[role]
                        counts = fold["origin_counts"][role]
                        require(
                            set(counts) == {"0", "1", "2"}
                            and all(type(value) is int and value > 0 for value in counts.values())
                            and sum(counts.values()) == partition["rows"],
                            "origin fold missing a class or count",
                        )
                        require(
                            partition["binary_labels"] == {"benign": partition["rows"]}
                            and all(
                                SHA.fullmatch(partition[key]) is not None
                                for key in ("event_ids_sha256", "records_sha256")
                            ),
                            "invalid origin partition provenance",
                        )
                    require(fold["fit_seconds"] > 0, "missing attempted-fold elapsed cost")
                    if fold["status"] == "ineligible":
                        require(
                            bool(fold["reason"]) and "balanced_accuracy" not in fold,
                            "ineligible fold fabricated score",
                        )
                        continue
                    require(fold["status"] == "evaluated", "unrecognized origin fold status")
                    confusion = np.asarray(fold["confusion_matrix"])
                    counts = np.asarray([fold["origin_counts"]["test"][str(i)] for i in range(3)])
                    require(
                        confusion.shape == (3, 3)
                        and np.issubdtype(confusion.dtype, np.integer)
                        and bool((confusion >= 0).all())
                        and np.array_equal(confusion.sum(axis=1), counts),
                        "origin confusion does not match test counts",
                    )
                    recall = confusion.diagonal() / counts
                    macro = float(
                        np.mean(2 * confusion.diagonal() / (counts + confusion.sum(axis=0)))
                    )
                    require(
                        np.allclose(recall, fold["per_origin_recall"], rtol=0, atol=1e-12)
                        and math.isclose(
                            float(recall.mean()), fold["balanced_accuracy"], abs_tol=1e-12
                        )
                        and math.isclose(macro, fold["macro_f1"], abs_tol=1e-12),
                        "origin score/confusion mismatch",
                    )
                    evaluated.append(fold["balanced_accuracy"])
                    require(
                        fold["fit_seconds"] > 0
                        and fold["memory"]["sampled_peak_rss_bytes"]
                        >= max(
                            fold["memory"]["rss_before_bytes"], fold["memory"]["rss_after_bytes"]
                        )
                        > 0,
                        "missing origin probe costs",
                    )
                    require(
                        [batch["batch_size"] for batch in fold["inference"]] == [1, 128],
                        "origin inference batches missing",
                    )
                    for batch in fold["inference"]:
                        require(
                            batch["scope"] == config["measurement"]["scope"]
                            and batch["warmups"] == 10
                            and batch["repetitions"] == 100
                            and batch["rows_per_second"] > 0
                            and 0
                            < batch["batch_latency_ms"]["p50"]
                            <= batch["batch_latency_ms"]["p95"]
                            <= batch["batch_latency_ms"]["p99"],
                            "invalid origin probe timing",
                        )
                    artifact = fold["artifact"]
                    name = f"{view['view']}-{entry['transform']}-fold{fold['fold']}.npz"
                    require(
                        artifact["file"] == name
                        and name not in artifact_names
                        and artifact["bytes"] > 0
                        and SHA.fullmatch(artifact["sha256"]) is not None,
                        "invalid origin artifact binding",
                    )
                    artifact_names.add(name)
                if len(evaluated) == 5:
                    mean, std = float(np.mean(evaluated)), float(np.std(evaluated))
                    require(
                        entry["status"] == "evaluated"
                        and math.isclose(mean, entry["balanced_accuracy_mean"], abs_tol=1e-12)
                        and math.isclose(std, entry["balanced_accuracy_std"], abs_tol=1e-12)
                        and entry["origin_warning"]
                        is (mean >= config["validation"]["block_threshold"]),
                        "origin fold summary or warning mismatch",
                    )
                else:
                    require(
                        entry["status"] == "ineligible_incomplete_folds"
                        and "balanced_accuracy_mean" not in entry
                        and "origin_warning" not in entry,
                        "incomplete origin folds have a fabricated aggregate score",
                    )
        require(
            len(artifact_names) == report["local_probe_artifacts"], "origin artifact count mismatch"
        )
    except (KeyError, TypeError, IndexError) as error:
        raise ValueError("incompatible origin evidence schema") from error


def verify(root: Path, *, artifact_directory: Path | None = None) -> dict[str, Any]:
    require(text_digest(root / REPORT_PATH) == REPORT_SHA256, "origin report hash mismatch")
    report = read_object(root / REPORT_PATH)
    validate_report(root, report)
    require(
        text_digest(root / HISTORICAL_PATH) == HISTORICAL_SHA256,
        "cost-incomplete historical attempt hash changed",
    )
    previous = read_object(root / HISTORICAL_PATH)
    require(
        scientific_projection(report) == scientific_projection(previous),
        "scientific results changed during the cost-only repeat",
    )
    if artifact_directory is not None:
        require(
            verify_probe_artifacts(artifact_directory, report["views"])
            == report["local_probe_artifacts"],
            "origin local artifact count mismatch",
        )
    return report


def scientific_projection(value: Any) -> Any:
    """Remove only execution/cost fields; preserve every input, score and artifact."""
    timing = {
        "code_commit",
        "started_at",
        "completed_at",
        "elapsed_seconds",
        "environment",
        "shared_tensor_build_seconds",
        "feature_build_seconds",
        "fit_seconds",
        "memory",
        "inference",
    }
    if isinstance(value, dict):
        return {
            key: scientific_projection(nested) for key, nested in value.items() if key not in timing
        }
    if isinstance(value, list):
        return [scientific_projection(nested) for nested in value]
    return value


def render_summary(report: dict[str, Any]) -> str:
    lines = [
        "# Independent-benign origin audit",
        "",
        f"Executed commit: `{report['code_commit']}`. Development diagnostic only.",
        "",
        "Mean balanced accuracy for predicting one of three benign capture origins.",
        "The fixed warning threshold is 0.90; a lower score does not prove invariance.",
        "",
        "| View | Standard | Robust | Clipped robust | Quantile normal |",
        "|---|---:|---:|---:|---:|",
    ]
    for view in report["views"]:
        entries = {entry["transform"]: entry for entry in view["transforms"]}
        cells = []
        for kind in report["registration"]["transforms"]:
            entry = entries.get(kind)
            cells.append(
                f"{entry['balanced_accuracy_mean']:.4f}"
                if entry and entry["status"] == "evaluated"
                else "unevaluable"
            )
        lines.append(f"| {view['view']} | " + " | ".join(cells) + " |")
    lines += [
        "",
        "Inputs: 181 hp4, 181 hp5, 30 capture-20 benign records; none entered encoder fitting.",
        "Grouped-fold/convergence failures remain explicit; no detector was retrained.",
        "",
        "Regenerate with `python -m scripts.verify_registered_origin --markdown`.",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", type=Path)
    parser.add_argument("--markdown", action="store_true")
    args = parser.parse_args()
    report = verify(Path.cwd(), artifact_directory=args.artifact_dir)
    print(
        render_summary(report)
        if args.markdown
        else "verified DEV2-ORIGIN-002: 8 views, explicit coverage failures, development only"
    )


if __name__ == "__main__":
    main()
