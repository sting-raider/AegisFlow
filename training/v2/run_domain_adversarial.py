"""Detector-v2 domain-adversarial training experiment (development evidence only).

Implements the gradient-reversal domain adversary over the fusion encoder and measures
whether reduced environment leakage preserves or improves the security task, including
the incidental-benign false-positive problem identified in MR2-002.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import numpy as np
import torch
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score
from sklearn.model_selection import StratifiedKFold, cross_val_score
from torch import Tensor
from torch.utils.data import DataLoader, TensorDataset

from training.v2.models import FusionNet, gradient_reversal
from training.v2.run_cross_environment import (
    BATCH_SIZE,
    LEARNING_RATE,
    SEED,
    fit_standardizer,
    split_fit,
)
from training.v2.tensors import (
    V2Dataset,
    build_dataset,
    class_capped_subset,
    deduplicate_records,
    load_records,
)

EPOCHS = 150
ADVERSARIAL_COEFFICIENTS = (0.0, 0.1, 1.0)


def train_adversarial(
    *,
    train_dataset: V2Dataset,
    scenario_labels: np.ndarray,
    lambd: float,
) -> FusionNet:
    model = FusionNet(
        max_length=20,
        features_per_packet=4,
        aggregate_dim=train_dataset.aggregate.shape[1],
        encoder="mlp",
    )
    center, scale = fit_standardizer(train_dataset.aggregate)

    def standardized(matrix: np.ndarray) -> np.ndarray:
        result: np.ndarray = ((matrix - center) / scale).astype(np.float64)
        return result

    generator = torch.Generator().manual_seed(SEED)
    benign_count = float((train_dataset.binary_label == 0).sum())
    malicious_count = max(float((train_dataset.binary_label == 1).sum()), 1.0)
    criterion = torch.nn.BCEWithLogitsLoss(pos_weight=Tensor([benign_count / malicious_count]))
    domain_criterion = torch.nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=LEARNING_RATE)

    unique_environments = {name: index for index, name in enumerate(sorted(set(scenario_labels)))}
    domain_ids = Tensor(
        np.asarray([unique_environments[name] for name in scenario_labels], dtype=np.float32)
    ).long()
    sequence = Tensor(train_dataset.sequence)
    mask = Tensor(train_dataset.mask)
    aggregate = Tensor(standardized(train_dataset.aggregate).astype(np.float32))
    labels = Tensor(train_dataset.binary_label)
    loader = DataLoader(
        TensorDataset(sequence, mask, aggregate, labels, domain_ids),
        batch_size=BATCH_SIZE,
        shuffle=True,
        generator=generator,
    )
    domain_head = torch.nn.Linear(48, len(unique_environments))
    domain_optimizer = torch.optim.Adam(domain_head.parameters(), lr=LEARNING_RATE)
    model.train()
    for _epoch in range(EPOCHS):
        for batch_sequence, batch_mask, batch_aggregate, batch_labels, batch_domains in loader:
            embedding = model.embed(batch_sequence, batch_mask, batch_aggregate)
            attack_logits: Tensor = model.head(embedding).squeeze(-1)
            loss_attack = criterion(attack_logits, batch_labels)
            reversed_embedding = gradient_reversal(embedding.detach(), lambd)
            domain_logits = domain_head(reversed_embedding)
            loss_domain = domain_criterion(domain_logits, batch_domains)
            domain_optimizer.zero_grad()
            loss_domain.backward()
            domain_optimizer.step()

            optimizer.zero_grad()
            embedding = model.embed(batch_sequence, batch_mask, batch_aggregate)
            attack_logits = model.head(embedding).squeeze(-1)
            loss = loss_attack
            if lambd > 0:
                reversed_embedding = gradient_reversal(embedding, lambd)
                domain_logits = domain_head(reversed_embedding)
                loss = loss + _domain_loss_for_encoder(
                    domain_head, reversed_embedding, batch_domains
                )
            loss.backward()
            optimizer.step()
    model.eval()
    return model


def _domain_loss_for_encoder(
    domain_head: torch.nn.Linear, reversed_embedding: Tensor, domains: Tensor
) -> Tensor:
    logits = domain_head(reversed_embedding)
    loss: Tensor = torch.nn.functional.cross_entropy(logits, domains)
    return loss


def main() -> None:
    sequence_dir = Path("data/sequences_v2")
    output_dir = Path("docs/research-v2/experiments")
    records = deduplicate_records(load_records(sorted(sequence_dir.glob("*.jsonl"))))
    s_mirai = "CTU-IoT-Malware-Capture-34-1"
    s_hakai = "CTU-IoT-Malware-Capture-8-1"
    hp4 = "CTU-Honeypot-Capture-4-1"
    hp5 = "CTU-Honeypot-Capture-5-1"
    torii_benign = "CTU-IoT-Malware-Capture-42-1"

    # Hard direction R2/HF2: fit on Hakai (+ benign envs), test on Mirai + hp4 site.
    fit_records = class_capped_subset(
        records,
        scenarios={s_hakai, hp4, hp5, torii_benign},
        per_class_cap=1500,
        seed=SEED,
    )
    train_records, calibration_records = split_fit(fit_records)
    test_records = [r for r in records if r["scenario"] in {s_mirai, hp4}]
    train_dataset = build_dataset(train_records)
    test_dataset = build_dataset(test_records)
    scenario_labels = np.asarray([r["scenario"] for r in train_records])

    folds = StratifiedKFold(n_splits=3, shuffle=True, random_state=SEED)
    report: dict[str, object] = {
        "schema_version": "1.0.0",
        "experiment_id": "DEV2-DANN-001",
        "generated_at": datetime.now(UTC).isoformat(),
        "seed": SEED,
        "epochs": EPOCHS,
        "rotation": "R2_transfer_to_mirai_hard_direction",
        "coefficients": {},
        "status": "development_evidence_only_no_candidate_selected",
    }
    coefficient_results: dict[str, object] = {}
    for lambd in ADVERSARIAL_COEFFICIENTS:
        trained_model = train_adversarial(
            train_dataset=train_dataset,
            scenario_labels=scenario_labels,
            lambd=lambd,
        )

        def embeddings_of(
            dataset: V2Dataset, bound_model: FusionNet = trained_model
        ) -> np.ndarray:
            embed = cast(Callable[..., Tensor], bound_model.embed)
            with torch.no_grad():
                center, scale = fit_standardizer(train_dataset.aggregate)
                aggregate = Tensor(((dataset.aggregate - center) / scale).astype(np.float32))
                output = embed(Tensor(dataset.sequence), Tensor(dataset.mask), aggregate)
                return np.asarray(output.numpy(), dtype=np.float64)

        train_embeddings = embeddings_of(train_dataset)
        origin_model = LogisticRegression(max_iter=3000, random_state=SEED)
        origin_scores = cross_val_score(
            origin_model,
            train_embeddings,
            scenario_labels,
            cv=folds,
            scoring="balanced_accuracy",
        )

        def scores_of(
            dataset: V2Dataset, bound_model: FusionNet = trained_model
        ) -> np.ndarray:
            call = cast(Callable[..., Tensor], bound_model)
            center, scale = fit_standardizer(train_dataset.aggregate)
            with torch.no_grad():
                logits = call(
                    Tensor(dataset.sequence),
                    Tensor(dataset.mask),
                    Tensor(((dataset.aggregate - center) / scale).astype(np.float32)),
                )
                probabilities = np.asarray(
                    torch.sigmoid(logits).numpy(), dtype=np.float64
                )
                return probabilities

        site_indices = [i for i, r in enumerate(test_records) if r["scenario"] == hp4]
        site_scores = scores_of(test_dataset)[site_indices]
        threshold = float(np.quantile(site_scores, 0.99))
        test_scores = scores_of(test_dataset)
        test_predictions = (test_scores >= threshold).astype(int)
        mirai_mask = np.asarray([r["scenario"] == s_mirai for r in test_records])
        mirai_malicious = mirai_mask & (test_dataset.binary_label == 1)
        incidental_benign = mirai_mask & (test_dataset.binary_label == 0)
        fit_predictions = (scores_of(train_dataset) >= threshold).astype(int)
        coefficient_results[f"lambda_{lambd}"] = {
            "embedding_origin_balanced_accuracy": round(float(origin_scores.mean()), 5),
            "mirai_known_channel_recall_at_site_p99": round(
                float(test_predictions[mirai_malicious].mean()), 5
            ),
            "incidental_benign_flagged_rate": round(
                float(test_predictions[incidental_benign].mean()), 5
            )
            if incidental_benign.any()
            else 0.0,
            "fit_split_macro_f1_at_same_threshold": round(
                float(f1_score(train_dataset.binary_label, fit_predictions, average="macro")),
                5,
            ),
        }
        print(f"lambda={lambd}", coefficient_results[f"lambda_{lambd}"], flush=True)

    report["coefficients"] = coefficient_results
    report_path = output_dir / "dev2-domain-adversarial-v1.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {report_path}")


if __name__ == "__main__":
    main()
