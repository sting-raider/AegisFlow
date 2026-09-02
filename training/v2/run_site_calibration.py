"""Detector-v2 Day-3 experiment: zero-shot versus site-calibrated detection.

Implements the mandatory mode comparison from docs/research-v2/MASTER_PLAN.md:

- Mode A/B (global): threshold selected on fit-environment calibration split.
- Mode C (site): threshold set as a quantile of APPROVED BENIGN scores from the
  target environment (observation-mode calibration data). No target attack data
  participates in any threshold decision.

Mode C answers the DEV2-SEQ-001 finding: ranking transfers across environments
(PR-AUC 0.85-1.0) while absolute probability thresholds do not. Site-relative
calibration is the designed remedy, not post-hoc tuning: only benign target data is
used, exactly like operator-approved observation mode in production.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import numpy as np
import torch
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, f1_score, roc_auc_score
from torch import Tensor

from training.v2.calibration import threshold_for_fpr
from training.v2.models import FusionNet, SequenceCNN, SequenceMLP
from training.v2.run_cross_environment import (
    BATCH_SIZE,
    LEARNING_RATE,
    SEED,
    calibration_threshold,
    ece_score,
    fit_standardizer,
    split_fit,
    torch_fit,
)
from training.v2.tensors import (
    SequenceRecord,
    V2Dataset,
    build_dataset,
    class_capped_subset,
    deduplicate_records,
    load_records,
)

SITE_PERCENTILES = (0.90, 0.95, 0.99, 0.995)
TRAINING_EPOCHS = 150


def evaluate_at_threshold(
    probabilities: np.ndarray,
    labels: np.ndarray,
    families: list[str],
    *,
    threshold: float,
) -> dict[str, float | int | object]:
    predictions = (probabilities >= threshold).astype(int)
    benign = labels == 0
    malicious = labels == 1
    by_family: dict[str, object] = {}
    for family in sorted({families[index] for index in np.where(malicious)[0]}):
        rows = malicious & np.asarray([families[i] == family for i in range(len(labels))])
        by_family[family] = {
            "rows": int(rows.sum()),
            "recall": round(float(predictions[rows].mean()), 5) if rows.any() else 0.0,
        }
    return {
        "threshold": float(threshold),
        "benign_fpr": round(float(predictions[benign].mean()), 5) if benign.any() else 0.0,
        "malicious_recall": round(float(predictions[malicious].mean()), 5)
        if malicious.any()
        else 0.0,
        "macro_f1": round(float(f1_score(labels, predictions, average="macro")), 5),
        "malicious_recall_by_family": by_family,
        "benign_rows": int(benign.sum()),
        "malicious_rows": int(malicious.sum()),
    }


def site_recall_curve(
    probabilities: np.ndarray,
    labels: np.ndarray,
    families: list[str],
    site_benign_scores: np.ndarray,
) -> dict[str, float | int | object]:
    """Recall when the threshold is a quantile of target-site approved benign scores.

    Reporting contract: ``nominal_site_fpr`` is a budget, not the measured rate.
    Tied score groups are excluded whole to meet the calibration budget; the exact
    unrounded cut and measured ``calibration_fpr`` are retained. The separately reported
    ``attack_env_incidental_benign_fpr`` measures the same threshold against benign
    rows that happen to exist inside the attack capture - a different environment,
    small sample, never a substitute for fresh site-benign validation.
    """

    curve: dict[str, float | int | object] = {}

    def evaluate_percentile(percentile: float, key: str) -> None:
        budget = round(1.0 - percentile, 5)
        threshold = threshold_for_fpr(site_benign_scores, budget)
        result = evaluate_at_threshold(
            probabilities, labels, families, threshold=threshold
        )
        curve[key] = {
            "nominal_site_fpr": budget,
            "calibration_fpr": float((site_benign_scores >= threshold).mean()),
            "threshold": result["threshold"],
            "malicious_recall": result["malicious_recall"],
            "malicious_recall_by_family": result["malicious_recall_by_family"],
            "attack_env_incidental_benign_rows": result["benign_rows"],
            "attack_env_incidental_benign_fpr": result["benign_fpr"],
            "degenerate_reference": bool(np.unique(site_benign_scores).size == 1),
        }

    for percentile in SITE_PERCENTILES:
        evaluate_percentile(percentile, f"site_p{int(percentile * 1000)}")
    return curve


def run(
    name: str,
    fit_scenarios: set[str],
    test_attack_scenario: str,
    test_benign_scenarios: set[str],
    records: Sequence[SequenceRecord],
) -> dict[str, object]:
    fit_records = class_capped_subset(
        records, scenarios=fit_scenarios, per_class_cap=1500, seed=SEED
    )
    train_records, calibration_records = split_fit(fit_records)
    test_attack_records = [
        record for record in records if record["scenario"] == test_attack_scenario
    ]
    site_benign_records = [
        record for record in records if record["scenario"] in test_benign_scenarios
    ]
    train_dataset = build_dataset(train_records)
    calibration_dataset = build_dataset(calibration_records)
    attack_dataset = build_dataset(test_attack_records)
    site_dataset = build_dataset(site_benign_records)

    torch.manual_seed(SEED)
    models: dict[str, torch.nn.Module] = {
        "sequence_mlp": SequenceMLP(max_length=20, features_per_packet=4),
        "sequence_cnn": SequenceCNN(features_per_packet=4),
        "fusion_mlp_seq_plus_aggregate": FusionNet(
            max_length=20,
            features_per_packet=4,
            aggregate_dim=train_dataset.aggregate.shape[1],
            encoder="mlp",
        ),
    }
    center, scale = fit_standardizer(train_dataset.aggregate)
    regression = LogisticRegression(max_iter=2000, random_state=SEED)

    def standardized(matrix: np.ndarray) -> np.ndarray:
        result: np.ndarray = ((matrix - center) / scale).astype(np.float64)
        return result

    regression.fit(standardized(train_dataset.aggregate), train_dataset.binary_label)

    def logreg_scores(dataset: V2Dataset) -> np.ndarray:
        probabilities: np.ndarray = regression.predict_proba(
            standardized(dataset.aggregate)
        )[:, 1]
        return probabilities

    scorers: dict[str, Callable[[V2Dataset], np.ndarray]] = {
        "aggregate_logreg_v1_style": logreg_scores,
    }
    for model_name, model in models.items():
        use_aggregate = "fusion" in model_name
        torch_fit(
            model,
            train_dataset,
            use_aggregate=use_aggregate,
            center=center if use_aggregate else None,
            scale=scale if use_aggregate else None,
            epochs=TRAINING_EPOCHS,
        )

        def net_scores(
            dataset: V2Dataset,
            _model: torch.nn.Module = model,
            _use: bool = use_aggregate,
        ) -> np.ndarray:
            call = cast(Callable[..., Tensor], _model)
            with torch.no_grad():
                sequence = Tensor(dataset.sequence)
                mask = Tensor(dataset.mask)
                logits: Tensor
                if _use:
                    aggregate = Tensor(standardized(dataset.aggregate).astype(np.float32))
                    logits = call(sequence, mask, aggregate)
                else:
                    logits = call(sequence, mask)
                probabilities = np.asarray(
                    torch.sigmoid(logits).numpy(), dtype=np.float64
                )
                return probabilities

        scorers[model_name] = net_scores

    results: dict[str, object] = {"rotation": name}
    for model_name, scorer in scorers.items():
        calibration_scores = scorer(calibration_dataset)
        global_rule = calibration_threshold(calibration_scores, calibration_dataset.binary_label)
        attack_scores = scorer(attack_dataset)
        attack_labels = attack_dataset.binary_label
        attack_families = attack_dataset.family
        site_benign_scores = scorer(site_dataset)
        pooled_scores = np.concatenate((attack_scores, site_benign_scores))
        pooled_labels = np.concatenate((attack_labels, np.zeros(len(site_benign_records))))
        results[model_name] = {
            "global_threshold_mode_ab": {
                **evaluate_at_threshold(
                    np.concatenate((attack_scores, site_benign_scores)),
                    pooled_labels,
                    list(attack_families) + ["benign_site"] * len(site_benign_records),
                    threshold=float(global_rule["threshold"]),
                ),
                "selection": global_rule,
            },
            "site_calibration_mode_c": site_recall_curve(
                attack_scores,
                attack_labels,
                attack_families,
                site_benign_scores,
            ),
            "ranking_diagnostics": {
                "roc_auc_pooled": round(float(roc_auc_score(pooled_labels, pooled_scores)), 5),
                "pr_auc_attack_only": round(
                    float(average_precision_score(attack_labels, attack_scores)), 5
                ),
                "ece_calibration_split": ece_score(
                    calibration_scores, calibration_dataset.binary_label
                ),
            },
        }
    return results


def main() -> None:
    sequence_dir = Path("data/sequences_v2")
    output_dir = Path("docs/research-v2/experiments")
    if (output_dir / "dev2-site-calibration-v1.json").exists():
        raise ValueError("historical site evidence exists; register a new experiment instead")
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = sorted(sequence_dir.glob("*.jsonl"))
    records = deduplicate_records(load_records(paths))
    rotations = {
        "R1_transfer_to_hakai": {
            "fit_scenarios": {
                "CTU-IoT-Malware-Capture-34-1",
                "CTU-Honeypot-Capture-4-1",
                "CTU-IoT-Malware-Capture-42-1",
            },
            "test_attack_scenario": "CTU-IoT-Malware-Capture-8-1",
            "test_benign_scenarios": {"CTU-Honeypot-Capture-5-1"},
        },
        "R2_transfer_to_mirai": {
            "fit_scenarios": {
                "CTU-IoT-Malware-Capture-8-1",
                "CTU-Honeypot-Capture-5-1",
                "CTU-IoT-Malware-Capture-42-1",
            },
            "test_attack_scenario": "CTU-IoT-Malware-Capture-34-1",
            "test_benign_scenarios": {"CTU-Honeypot-Capture-4-1"},
        },
    }
    report = {
        "schema_version": "1.0.0",
        "experiment_id": "DEV2-SITE-001",
        "generated_at": datetime.now(UTC).isoformat(),
        "seed": SEED,
        "training_epochs": TRAINING_EPOCHS,
        "batch_size": BATCH_SIZE,
        "learning_rate": LEARNING_RATE,
        "site_percentiles": [p * 100 for p in SITE_PERCENTILES],
        "protocol_note": (
            "Mode C uses ONLY approved benign target-site scores to place thresholds; "
            "no target attack rows participate in any selection decision. "
            "nominal_site_fpr holds on the calibration pool by construction; fresh "
            "site-benign validation and larger calibration pools remain required."
        ),
        "status": "development_evidence_only_no_candidate_selected",
    }
    rotation_results: dict[str, object] = {}
    for name, config in rotations.items():
        print(f"running {name} ...", flush=True)
        rotation_results[name] = run(
            name,
            set(config["fit_scenarios"]),
            str(config["test_attack_scenario"]),
            set(config["test_benign_scenarios"]),
            records,
        )
        print(json.dumps(rotation_results[name], indent=2, sort_keys=True), flush=True)
    report["rotations"] = rotation_results
    report_path = output_dir / "dev2-site-calibration-v1.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {report_path}")


if __name__ == "__main__":
    main()
