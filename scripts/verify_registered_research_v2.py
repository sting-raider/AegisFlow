"""Bind corrected development evidence; never grant model or production acceptance."""

from __future__ import annotations

import argparse
import math
import re
from pathlib import Path
from typing import Any

import numpy as np

from training.v2.provenance import read_object, sha256_file
from training.v2.registered_family import (
    REGISTRATION_SHA256,
    VERDICTS,
    load_registration,
    text_digest,
)

REPORT_PATH = "docs/research-v2/registered-results/DEV2-FAMILY-002.json"
REPORT_SHA256 = "6c1e2d5a576cb7c7afde9968151665f2e3afb64e0d7a737da17cb332dcadde73"
EXECUTION_COMMIT = "365903128b0db36128e0846960a89b72fe8a7a74"
SHA = re.compile(r"[0-9a-f]{64}")
PRIVATE_KEYS = {
    "event_ids",
    "event_id",
    "src_ip",
    "dst_ip",
    "source_ip",
    "destination_ip",
    "predictions",
    "payload",
    "packet_payload",
    "seq_sizes",
    "seq_iats_ms",
    "password",
    "secret",
    "token",
    "records",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def safe_aggregate(value: Any, path: str = "report") -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            # Preparation's 'records' is an aggregate count, never a row array.
            require(
                key not in PRIVATE_KEYS or (key == "records" and type(nested) is int),
                f"private field in {path}.{key}",
            )
            safe_aggregate(nested, f"{path}.{key}")
    elif isinstance(value, list):
        for nested in value:
            safe_aggregate(nested, path)
    elif isinstance(value, float):
        require(math.isfinite(value), f"nonfinite evidence in {path}")


def validate_rate(value: dict[str, Any], n: int, expected_count: int | None = None) -> None:
    count = value["count"]
    require(type(count) is int and 0 <= count <= n and value["rows"] == n, "invalid metric counts")
    require(math.isclose(value["rate"], count / n, abs_tol=1e-12), "rate/count mismatch")
    if expected_count is not None:
        require(count == expected_count, "verdict and metric counts disagree")
    low, high = value["wilson_95"]
    require(
        0 <= low <= high <= 1 and low - 1e-12 <= count / n <= high + 1e-12,
        "invalid uncertainty interval",
    )


def validate_metrics(metrics: dict[str, Any]) -> None:
    totals = {name: 0 for name in VERDICTS}
    for kind in ("benign", "attack"):
        if kind not in metrics:
            continue
        group = metrics[kind]
        counts = group["four_verdict_counts"]
        n = group["rows"]
        require(type(n) is int and n > 0 and set(counts) == set(VERDICTS), "invalid verdict rows")
        require(
            all(type(c) is int and c >= 0 for c in counts.values()) and sum(counts.values()) == n,
            "invalid verdict counts",
        )
        direct = counts["known_attack"] + counts["suspicious_unknown"]
        inclusive = n - counts["benign"]
        for metric, count in (
            ("direct_suspicious_unknown", counts["suspicious_unknown"]),
            ("direct_detection", direct),
            ("detection_or_review", inclusive),
            ("known_channel", counts["known_attack"]),
            ("ood_channel", None),
        ):
            validate_rate(group[metric], n, count)
        if kind == "benign":
            validate_rate(group["direct_union_fpr"], n, direct)
            validate_rate(group["review_inclusive_rate"], n, inclusive)
            require(
                math.isclose(group["false_alerts_per_10000_benign"], direct * 10000 / n),
                "workload metric mismatch",
            )
            require(group["false_alerts_per_hour"] is None, "unsupported chronological rate")
        for name in VERDICTS:
            totals[name] += counts[name]
    require(
        totals == metrics["four_verdict_counts"] and sum(totals.values()) == metrics["rows"],
        "aggregate verdict totals disagree",
    )


def validate_report(root: Path, report: dict[str, Any]) -> None:
    try:
        safe_aggregate(report)
        config = load_registration(root)
        require(
            report["registration"] == config
            and report["registration_sha256_utf8_lf"] == REGISTRATION_SHA256,
            "registration mismatch",
        )
        require(report["code_commit"] == EXECUTION_COMMIT, "execution commit mismatch")
        require(
            report["preparation_manifest"]
            == read_object(root / config["prepared_manifest"]["path"]),
            "preparation binding mismatch",
        )
        require(
            report["execution_status"] == "completed"
            and report["scientific_status"] == "development_only_not_candidate_selected",
            "invalid research status",
        )
        require(
            report["elapsed_seconds"] > 0 and report["environment"]["torch_threads"] == 1,
            "missing execution measurements",
        )
        expected = {
            (family, index)
            for family in config["splits"]["held_family_attack_scenarios"]
            for index in (1, 2)
        }
        observed = set()
        artifacts: dict[str, set[str]] = {}
        for rotation in report["rotations"]:
            family = rotation["held_family"]
            index = int(rotation["rotation"].rsplit("_", 1)[1])
            key = (family, index)
            require(key in expected and key not in observed, "unexpected or duplicate rotation")
            observed.add(key)
            orientation = config["splits"]["site_orientations"][index - 1]
            require(rotation["site_orientation"] == orientation, "site orientation mismatch")
            parts = rotation["partition_provenance"]
            require(
                set(parts) == {"fit", "held_attack", "site_calibration", "benign_test"},
                "partition manifest incomplete",
            )
            for partition in parts.values():
                require(
                    partition["rows"] > 0
                    and all(
                        SHA.fullmatch(partition[k]) is not None
                        for k in ("event_ids_sha256", "records_sha256")
                    ),
                    "invalid partition binding",
                )
                require(
                    sum(partition["families"].values())
                    == partition["rows"]
                    == sum(partition["binary_labels"].values()),
                    "partition counts disagree",
                )
            require(
                family not in parts["fit"]["families"]
                and set(parts["fit"]["scenarios"]) <= set(config["splits"]["fit_source_scenarios"]),
                "held family or site in fit",
            )
            require(
                set(parts["held_attack"]["families"]) == {family}
                and set(parts["held_attack"]["binary_labels"]) == {"malicious"},
                "held attack family mismatch",
            )
            for role, site in (("site_calibration", "calibration"), ("benign_test", "benign_test")):
                require(
                    parts[role]["scenarios"] == [orientation[site]]
                    and set(parts[role]["families"]) == {"benign"}
                    and set(parts[role]["binary_labels"]) == {"benign"},
                    "nonbenign site",
                )
            for metric_key in ("calibration", "test"):
                validate_metrics(rotation[metric_key])
            require(
                rotation["test"]["attack"]["rows"] == parts["held_attack"]["rows"]
                and rotation["test"]["benign"]["rows"] == parts["benign_test"]["rows"]
                and rotation["calibration"]["rows"] == parts["site_calibration"]["rows"],
                "evaluation partition counts disagree",
            )
            calibration = rotation["calibration"]["benign"]
            require(
                calibration["direct_union_fpr"]["rate"]
                <= config["calibration"]["direct_union_budget"]
                and calibration["review_inclusive_rate"]["rate"]
                <= config["calibration"]["review_inclusive_union_budget"],
                "budget violated",
            )
            cuts = rotation["thresholds"]
            require(
                set(cuts) == {"known_direct", "known_review", "ood_direct", "ood_review"}
                and cuts["known_direct"] >= cuts["known_review"]
                and cuts["ood_direct"] >= cuts["ood_review"],
                "invalid thresholds",
            )
            memory = rotation["memory"]
            require(
                memory["sampled_peak_rss_bytes"]
                >= max(memory["rss_before_bytes"], memory["rss_after_bytes"])
                > 0
                and memory["samples"] > 0
                and rotation["fit_wall_seconds"] > 0,
                "missing cost evidence",
            )
            require(
                [b["batch_size"] for b in rotation["inference"]] == [1, 128],
                "missing benchmark size",
            )
            for batch in rotation["inference"]:
                require(
                    batch["warmup_calls"] == 10
                    and batch["measured_calls"] == 100
                    and batch["scope"] == config["measurement"]["inference_scope"]
                    and batch["throughput_flows_per_second"] > 0
                    and 0
                    < batch["batch_latency_ms"]["p50"]
                    <= batch["batch_latency_ms"]["p95"]
                    <= batch["batch_latency_ms"]["p99"],
                    "invalid benchmark",
                )
            artifact = rotation["artifact"]
            require(
                artifact["file"] == f"{rotation['rotation']}.npz"
                and artifact["bytes"] > 0
                and SHA.fullmatch(artifact["sha256"]) is not None
                and artifact["format"] == "numpy_numeric_arrays_no_pickle",
                "invalid artifact",
            )
            artifacts.setdefault(family, set()).add(artifact["sha256"])
        require(
            observed == expected and len(report["rotations"]) == 6, "incomplete rotation matrix"
        )
        require(all(len(hashes) == 1 for hashes in artifacts.values()), "site changed fitted model")
    except (KeyError, TypeError, IndexError) as error:
        raise ValueError("incompatible registered evidence schema") from error


def verify(root: Path, *, artifact_directory: Path | None = None) -> dict[str, Any]:
    require(text_digest(root / REPORT_PATH) == REPORT_SHA256, "registered report hash mismatch")
    report = read_object(root / REPORT_PATH)
    validate_report(root, report)
    if artifact_directory is not None:
        for rotation in report["rotations"]:
            artifact = rotation["artifact"]
            path = artifact_directory / artifact["file"]
            require(
                path.resolve().parent == artifact_directory.resolve(), "artifact escapes directory"
            )
            require(
                sha256_file(path) == artifact["sha256"]
                and path.stat().st_size == artifact["bytes"],
                "local model artifact hash/size mismatch",
            )
            with np.load(path, allow_pickle=False) as saved:
                require(
                    set(saved.files) == set(artifact["arrays"]), "artifact array names mismatch"
                )
                for key, meta in artifact["arrays"].items():
                    require(
                        list(saved[key].shape) == meta["shape"]
                        and str(saved[key].dtype) == meta["dtype"]
                        and np.isfinite(saved[key]).all(),
                        "invalid model arrays",
                    )
    return report


def render_summary(report: dict[str, Any]) -> str:
    lines = [
        "# Corrected strict-family development result",
        "",
        f"Executed commit: `{report['code_commit']}`. Development only; no model selected.",
        "",
        "| Held family / calibration site | Attacks | Direct unknown | "
        "Detection or review | Benign FPR |",
        "|---|---:|---:|---:|---:|",
    ]
    for r in report["rotations"]:
        attack, benign = r["test"]["attack"], r["test"]["benign"]
        site = r["site_orientation"]["calibration"].removeprefix("CTU-Honeypot-Capture-")
        lines.append(
            f"| {r['held_family']} / hp{site} | {attack['rows']:,} | "
            f"{attack['direct_suspicious_unknown']['rate']:.2%} | "
            f"{attack['detection_or_review']['rate']:.2%} | "
            f"{benign['direct_union_fpr']['rate']:.2%} |"
        )
    lines += [
        "",
        "Benign test is the other honeypot (181 rows). Same attacks are reused across",
        "site orientations; they are not independent additional attack samples.",
        "",
        "Regenerate this table with `python -m scripts.verify_registered_research_v2 --markdown`.",
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
        else "verified DEV2-FAMILY-002: 6 rotations, bound clean code/data/config; development only"
    )


if __name__ == "__main__":
    main()
