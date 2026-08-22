"""Detector-v2 Day-2 cross-environment experiment (development evidence only).

Predeclared rotations (docs/research-v2/MASTER_PLAN.md):

- R1 ``transfer_to_hakai``: fit {34-1 attacks, hp4+42-1 benign} -> test
  {8-1 Hakai C&C (family unseen), hp5 benign (environment unseen)}.
- R2 ``transfer_to_mirai``: fit {8-1 C&C, hp5+42-1 benign} -> test
  {34-1 Mirai C&C/DDoS/port-scan, hp4 benign (environment unseen)}.

Every model uses an untuned 0.5 threshold. No frozen v1 evidence participates.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import numpy as np
import torch
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, f1_score
from torch import Tensor
from torch.utils.data import DataLoader, TensorDataset

from training.v2.models import FusionNet, SequenceCNN, SequenceMLP
from training.v2.tensors import (
    SequenceRecord,
    V2Dataset,
    build_dataset,
    class_capped_subset,
    deduplicate_records,
    load_records,
)

SEED = 20260822
EPOCHS = 40
BATCH_SIZE = 256
LEARNING_RATE = 1e-3
PER_CLASS_CAP = 1500

FIT_CALIBRATION_FRACTION = 20
CALIBRATION_BENIGN_FPR_BUDGET = 0.01


def calibration_threshold(
    probabilities: np.ndarray, labels: np.ndarray
) -> dict[str, float | bool]:
    """Predeclared rule: maximize calibration macro-F1 subject to FPR <= 1%.

    Cut points are evaluated only at observed score values (tie-group boundaries) so
    the selected threshold reproduces exactly the `>=` semantics used everywhere else;
    midpoints between tied scores previously mis-scored candidates under heavy ties.
    If no candidate satisfies the budget, fall back to the FPR closest to budget and
    report that visibly; the test set is never consulted.
    """

    positives = float((labels == 1).sum())
    negatives = max(float((labels == 0).sum()), 1.0)
    order = np.argsort(-probabilities, kind="stable")
    sorted_scores = probabilities[order]
    sorted_labels = labels[order]
    tp_cumulative = np.cumsum(sorted_labels)
    fp_cumulative = np.cumsum(1.0 - sorted_labels)
    boundaries = np.where(np.diff(sorted_scores) != 0)[0]
    cut_indices = np.concatenate((boundaries, [len(sorted_scores) - 1]))
    tp = tp_cumulative[cut_indices]
    fp = fp_cumulative[cut_indices]
    fn = positives - tp
    tn = negatives - fp
    precision = tp / np.maximum(tp + fp, 1e-12)
    recall = tp / max(positives, 1.0)
    f1_positive = np.where(
        tp > 0, 2 * precision * recall / np.maximum(precision + recall, 1e-12), 0.0
    )
    f1_negative = np.where(tn > 0, 2 * tn / np.maximum(2 * tn + fn + fp, 1e-12), 0.0)
    macro_f1 = (f1_positive + f1_negative) / 2.0
    false_positive_rates = fp / negatives
    feasible = false_positive_rates <= CALIBRATION_BENIGN_FPR_BUDGET
    if feasible.any():
        best_index = int(np.argmax(np.where(feasible, macro_f1, -np.inf)))
        budget_met = True
    else:
        best_index = int(
            np.argmin(np.abs(false_positive_rates - CALIBRATION_BENIGN_FPR_BUDGET))
        )
        budget_met = False
    return {
        "threshold": round(float(sorted_scores[best_index]), 6),
        "calibration_macro_f1": round(float(macro_f1[best_index]), 5),
        "calibration_recall": round(float(recall[best_index]), 5),
        "calibration_fpr": round(float(false_positive_rates[best_index]), 5),
        "budget_met": budget_met,
    }


def split_fit(
    records: Sequence[SequenceRecord],
) -> tuple[list[SequenceRecord], list[SequenceRecord]]:
    """Deterministic hash split of fit environments into train and calibration."""

    train: list[SequenceRecord] = []
    calibration: list[SequenceRecord] = []
    for record in records:
        digest = hashlib.sha256(str(record["event_id"]).encode()).hexdigest()[:8]
        if int(digest, 16) % 100 < FIT_CALIBRATION_FRACTION:
            calibration.append(record)
        else:
            train.append(record)
    for subset, name in ((train, "train"), (calibration, "calibration")):
        labels = {str(record["binary_label"]) for record in subset}
        if labels != {"benign", "malicious"}:
            raise ValueError(f"{name} split lost a class: {labels}")
    return train, calibration


def ece_score(probabilities: np.ndarray, labels: np.ndarray, bins: int = 10) -> float:
    edges = np.linspace(0.0, 1.0, bins + 1)
    total = len(labels)
    score = 0.0
    for index in range(bins):
        low, high = edges[index], edges[index + 1]
        upper_inclusive = index == bins - 1
        if upper_inclusive:
            mask = (probabilities >= low) & (probabilities <= high)
        else:
            mask = (probabilities >= low) & (probabilities < high)
        if not mask.any():
            continue
        gap = abs(float(labels[mask].mean()) - float(probabilities[mask].mean()))
        score += float(mask.sum()) / total * gap
    return round(score, 5)


def fit_standardizer(matrix: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    center = matrix.mean(axis=0)
    scale = matrix.std(axis=0)
    scale[scale < 1e-9] = 1.0
    return center, scale


def torch_fit(
    model: torch.nn.Module,
    dataset: V2Dataset,
    *,
    use_aggregate: bool,
    center: np.ndarray | None = None,
    scale: np.ndarray | None = None,
) -> None:
    generator = torch.Generator().manual_seed(SEED)
    benign_count = float((dataset.binary_label == 0).sum())
    malicious_count = max(float((dataset.binary_label == 1).sum()), 1.0)
    positive_weight = Tensor([benign_count / malicious_count])
    criterion = torch.nn.BCEWithLogitsLoss(pos_weight=positive_weight)
    optimizer = torch.optim.Adam(model.parameters(), lr=LEARNING_RATE)
    sequence = Tensor(dataset.sequence)
    mask = Tensor(dataset.mask)
    labels = Tensor(dataset.binary_label)
    if use_aggregate:
        if center is None or scale is None:
            raise ValueError("aggregate fusion fitting requires train-fit standardizer")
        aggregate_all = Tensor(((dataset.aggregate - center) / scale).astype(np.float32))
        tensor_dataset = TensorDataset(sequence, mask, aggregate_all, labels)
    else:
        tensor_dataset = TensorDataset(sequence, mask, labels)
    loader = DataLoader(tensor_dataset, batch_size=BATCH_SIZE, shuffle=True, generator=generator)
    call = cast(Callable[..., Tensor], model)
    model.train()
    for _epoch in range(EPOCHS):
        for batch in loader:
            optimizer.zero_grad()
            logits: Tensor
            if use_aggregate:
                batch_sequence, batch_mask, batch_aggregate, batch_labels = batch
                logits = call(batch_sequence, batch_mask, batch_aggregate)
            else:
                batch_sequence, batch_mask, batch_labels = batch
                logits = call(batch_sequence, batch_mask)
            loss = criterion(logits, batch_labels)
            loss.backward()
            optimizer.step()
    model.eval()


def torch_predict(
    model: torch.nn.Module,
    dataset: V2Dataset,
    *,
    center: np.ndarray,
    scale: np.ndarray,
    use_aggregate: bool,
) -> np.ndarray:
    call = cast(Callable[..., Tensor], model)
    with torch.no_grad():
        sequence = Tensor(dataset.sequence)
        mask = Tensor(dataset.mask)
        if use_aggregate:
            aggregate = Tensor(((dataset.aggregate - center) / scale).astype(np.float32))
            logits = call(sequence, mask, aggregate)
        else:
            logits = call(sequence, mask)
        probabilities = np.asarray(torch.sigmoid(logits).numpy(), dtype=np.float64)
        return probabilities


def evaluate(
    probabilities: np.ndarray,
    labels: np.ndarray,
    *,
    threshold: float = 0.5,
    families: list[str] | None = None,
) -> dict[str, float | int | object]:
    predictions = (probabilities >= threshold).astype(int)
    benign = labels == 0
    malicious = labels == 1
    false_positive_rate = float(predictions[benign].mean()) if benign.any() else 0.0
    recall = float(predictions[malicious].mean()) if malicious.any() else 0.0
    result: dict[str, float | int | object] = {
        "threshold": round(threshold, 6),
        "benign_fpr": round(false_positive_rate, 5),
        "malicious_recall": round(recall, 5),
        "macro_f1": round(float(f1_score(labels, predictions, average="macro")), 5),
        "pr_auc": (
            round(float(average_precision_score(labels, probabilities)), 5)
            if labels.min() != labels.max()
            else 0.0
        ),
        "ece_10bin": ece_score(probabilities, labels),
        "rows": len(labels),
        "benign_rows": int(benign.sum()),
        "malicious_rows": int(malicious.sum()),
    }
    if families is not None and malicious.any():
        family_recall: dict[str, object] = {}
        for family in sorted({families[index] for index in np.where(malicious)[0]}):
            family_mask = malicious & np.asarray(
                [families[index] == family for index in range(len(labels))]
            )
            family_predictions = predictions[family_mask]
            family_recall[family] = {
                "rows": int(family_mask.sum()),
                "recall": round(float(family_predictions.mean()), 5)
                if len(family_predictions)
                else 0.0,
            }
        result["malicious_recall_by_family"] = family_recall
    return result


def run_rotation(
    name: str,
    fit_scenarios: set[str],
    test_attack_scenario: str,
    test_benign_scenarios: set[str],
    records: Sequence[SequenceRecord],
    output_dir: Path,
) -> dict[str, object]:
    fit_records = class_capped_subset(
        records, scenarios=fit_scenarios, per_class_cap=PER_CLASS_CAP, seed=SEED
    )
    train_records, calibration_records = split_fit(fit_records)
    test_records = [
        record
        for record in records
        if record["scenario"] == test_attack_scenario
        or record["scenario"] in test_benign_scenarios
    ]
    train_dataset = build_dataset(train_records)
    calibration_dataset = build_dataset(calibration_records)
    test_dataset = build_dataset(test_records)

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
    results: dict[str, object] = {
        "rotation": name,
        "protocol": "fit_side_calibration_threshold_fpr_budget_1pct",
        "fit_train_counts": {
            "benign": int((train_dataset.binary_label == 0).sum()),
            "malicious": int((train_dataset.binary_label == 1).sum()),
        },
        "fit_calibration_counts": {
            "benign": int((calibration_dataset.binary_label == 0).sum()),
            "malicious": int((calibration_dataset.binary_label == 1).sum()),
        },
    }
    test_counts: dict[str, int] = {}
    for scenario in sorted({*test_benign_scenarios, test_attack_scenario}):
        test_counts[scenario] = sum(
            1 for record in test_records if record["scenario"] == scenario
        )
    results["test_counts_by_scenario"] = test_counts

    center, scale = fit_standardizer(train_dataset.aggregate)

    def standardized(matrix: np.ndarray) -> np.ndarray:
        result: np.ndarray = (matrix - center) / scale
        return result

    regression = LogisticRegression(max_iter=2000, random_state=SEED)
    regression.fit(standardized(train_dataset.aggregate), train_dataset.binary_label)
    calibration_probabilities = regression.predict_proba(
        standardized(calibration_dataset.aggregate)
    )[:, 1]
    chosen = calibration_threshold(
        calibration_probabilities, calibration_dataset.binary_label
    )
    aggregate_probabilities = regression.predict_proba(
        standardized(test_dataset.aggregate)
    )[:, 1]
    results["aggregate_logreg_v1_style"] = {
        "threshold_selection": chosen,
        "test_at_calibrated_threshold": evaluate(
            aggregate_probabilities,
            test_dataset.binary_label,
            threshold=chosen["threshold"],
            families=test_dataset.family,
        ),
    }

    for model_name, model in models.items():
        use_aggregate = "fusion" in model_name
        torch_fit(
            model,
            train_dataset,
            use_aggregate=use_aggregate,
            center=center if use_aggregate else None,
            scale=scale if use_aggregate else None,
        )
        train_self = evaluate(
            torch_predict(
                model,
                train_dataset,
                center=center,
                scale=scale,
                use_aggregate=use_aggregate,
            ),
            train_dataset.binary_label,
        )
        calibration_probabilities_model = torch_predict(
            model,
            calibration_dataset,
            center=center,
            scale=scale,
            use_aggregate=use_aggregate,
        )
        chosen_model = calibration_threshold(
            calibration_probabilities_model, calibration_dataset.binary_label
        )
        probabilities = torch_predict(
            model,
            test_dataset,
            center=center,
            scale=scale,
            use_aggregate=use_aggregate,
        )
        embedding_path = output_dir / f"{name}-{model_name}-embeddings.npz"
        embed = cast(Callable[..., Tensor], model.embed)
        with torch.no_grad():
            sequence = Tensor(test_dataset.sequence)
            mask = Tensor(test_dataset.mask)
            if use_aggregate:
                aggregate = Tensor(standardized(test_dataset.aggregate).astype(np.float32))
                embeddings = embed(sequence, mask, aggregate).numpy()
            else:
                embeddings = embed(sequence, mask).numpy()
        np.savez_compressed(
            embedding_path,
            embeddings=embeddings.astype(np.float32),
            binary_label=test_dataset.binary_label,
            scenario=np.asarray(test_dataset.scenario),
            family=np.asarray(test_dataset.family),
        )
        results[model_name] = {
            "train_in_sample_diagnostic": {
                "benign_fpr": train_self["benign_fpr"],
                "malicious_recall": train_self["malicious_recall"],
            },
            "threshold_selection": chosen_model,
            "test_at_untuned_0p5": evaluate(probabilities, test_dataset.binary_label),
            "test_at_calibrated_threshold": evaluate(
                probabilities,
                test_dataset.binary_label,
                threshold=chosen_model["threshold"],
                families=test_dataset.family,
            ),
        }

    per_environment = {}
    for label_value, label_name in ((0, "benign"), (1, "malicious")):
        mask = test_dataset.binary_label == label_value
        per_environment[label_name] = {
            "rows": int(mask.sum()),
            "by_scenario": {
                scenario: sum(
                    1
                    for index in np.where(mask)[0]
                    if test_dataset.scenario[index] == scenario
                )
                for scenario in sorted(set(test_dataset.scenario))
            },
        }
    results["test_environment_composition"] = per_environment
    return results


def main() -> None:
    sequence_dir = Path("data/sequences_v2")
    output_dir = Path("docs/research-v2/experiments")
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = sorted(path for path in sequence_dir.glob("*.jsonl"))
    if not paths:
        raise SystemExit("no prepared sequence files found; run prepare_sequences.py first")
    records = deduplicate_records(load_records(paths))
    print(f"records after deduplication: {len(records)}")

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
        "experiment_id": "DEV2-SEQ-001",
        "generated_at": datetime.now(UTC).isoformat(),
        "seed": SEED,
        "epochs": EPOCHS,
        "batch_size": BATCH_SIZE,
        "per_class_cap": PER_CLASS_CAP,
        "status": "development_evidence_only_no_candidate_selected",
    }
    rotation_results: dict[str, object] = {}
    for name, config in rotations.items():
        print(f"running {name} ...", flush=True)
        rotation_results[name] = run_rotation(
            name,
            set(config["fit_scenarios"]),
            str(config["test_attack_scenario"]),
            set(config["test_benign_scenarios"]),
            records,
            output_dir,
        )
        print(json.dumps(rotation_results[name], indent=2, sort_keys=True), flush=True)

    report["rotations"] = rotation_results
    report_path = output_dir / "dev2-sequence-crossenv-v1.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {report_path}")


if __name__ == "__main__":
    main()
