"""Detector-v2 held-attack-family evaluation with two-channel open-set verdicts.

Development evidence only. Whole families are removed from fitting; the held family
must surface through either the known-attack channel (classifier score above a
site-calibrated threshold) or an OOD channel (Mahalanobis distance in the fusion
embedding, calibrated on approved target-site benign scores). Neither channel ever
sees target attack data.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import numpy as np
import torch
from torch import Tensor

from training.v2.models import FusionNet
from training.v2.partitions import assert_strict_family_rotation
from training.v2.run_cross_environment import (
    BATCH_SIZE,
    LEARNING_RATE,
    SEED,
    fit_standardizer,
    torch_fit,
)
from training.v2.tensors import (
    SequenceRecord,
    V2Dataset,
    build_dataset,
    deduplicate_records,
    load_records,
)

SITE_PERCENTILE = 0.99


def select_fit(
    records: Sequence[SequenceRecord],
    *,
    scenarios: set[str],
    allowed_families: set[str] | None,
    per_class_cap: int,
    seed: int,
) -> list[SequenceRecord]:
    counts = {"benign": 0, "malicious": 0}
    ordered = sorted(records, key=lambda item: str(item["event_id"]))
    generator = np.random.default_rng(seed)
    permutation = generator.permutation(len(ordered)).tolist()
    selected: list[SequenceRecord] = []
    for position in permutation:
        record = ordered[position]
        if str(record["scenario"]) not in scenarios:
            continue
        label = str(record["binary_label"])
        if label not in counts or counts[label] >= per_class_cap:
            continue
        if allowed_families is not None and str(record["family"]) not in allowed_families:
            continue
        counts[label] += 1
        selected.append(record)
    if counts["benign"] == 0 or counts["malicious"] == 0:
        raise ValueError("held-family fit requires both classes")
    return selected


def mahalanobis_fit(embeddings: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    center = embeddings.mean(axis=0)
    covariance = np.cov((embeddings - center).T)
    covariance += np.eye(covariance.shape[0]) * 1e-6
    inverse = np.linalg.inv(covariance)
    return center, inverse


def mahalanobis_distances(
    embeddings: np.ndarray, center: np.ndarray, inverse: np.ndarray
) -> np.ndarray:
    delta = embeddings - center
    distances = np.sqrt(np.einsum("ij,jk,ik->i", delta, inverse, delta))
    return np.asarray(distances, dtype=np.float64)


def run_rotation(
    name: str,
    fit_scenarios: set[str],
    fit_families: set[str] | None,
    held_family: str,
    held_scenarios: set[str],
    site_benign_scenario: str,
    benign_test_scenario: str,
    records: Sequence[SequenceRecord],
) -> dict[str, object]:
    fit_records = select_fit(
        records,
        scenarios=fit_scenarios,
        allowed_families=fit_families,
        per_class_cap=1500,
        seed=SEED,
    )
    held_records = [
        r
        for r in records
        if r["scenario"] in held_scenarios
        and r["binary_label"] == "malicious"
        and r["family"] == held_family
    ]
    site_records = [
        r
        for r in records
        if r["scenario"] == site_benign_scenario and r["binary_label"] == "benign"
    ]
    benign_test_records = [
        r
        for r in records
        if r["scenario"] == benign_test_scenario and r["binary_label"] == "benign"
    ]
    assert_strict_family_rotation(
        fit=fit_records,
        site_calibration=site_records,
        held_attack=held_records,
        benign_test=benign_test_records,
        held_family=held_family,
    )

    fit_dataset = build_dataset(fit_records)
    held_dataset = build_dataset(held_records + benign_test_records)
    site_dataset = build_dataset(site_records)

    torch.manual_seed(SEED)
    model = FusionNet(
        max_length=20,
        features_per_packet=4,
        aggregate_dim=fit_dataset.aggregate.shape[1],
        encoder="mlp",
    )
    center, scale = fit_standardizer(fit_dataset.aggregate)

    def standardized(matrix: np.ndarray) -> np.ndarray:
        result: np.ndarray = ((matrix - center) / scale).astype(np.float64)
        return result

    torch_fit(
        model,
        fit_dataset,
        use_aggregate=True,
        center=center,
        scale=scale,
        epochs=150,
    )
    embed = cast(Callable[..., Tensor], model.embed)

    def embeddings_of(dataset: V2Dataset) -> np.ndarray:
        with torch.no_grad():
            aggregate = Tensor(standardized(dataset.aggregate).astype(np.float32))
            output = embed(Tensor(dataset.sequence), Tensor(dataset.mask), aggregate)
            return np.asarray(output.numpy(), dtype=np.float64)

    def scores_of(dataset: V2Dataset) -> np.ndarray:
        call = cast(Callable[..., Tensor], model)
        with torch.no_grad():
            logits = call(
                Tensor(dataset.sequence),
                Tensor(dataset.mask),
                Tensor(standardized(dataset.aggregate).astype(np.float32)),
            )
            probabilities = np.asarray(torch.sigmoid(logits).numpy(), dtype=np.float64)
            return probabilities

    benign_fit_embeddings = embeddings_of(fit_dataset)[fit_dataset.binary_label == 0]
    ood_center, ood_inverse = mahalanobis_fit(benign_fit_embeddings)

    site_scores = scores_of(site_dataset)
    site_ood = mahalanobis_distances(
        embeddings_of(site_dataset), ood_center, ood_inverse
    )
    threshold_score = float(np.quantile(site_scores, SITE_PERCENTILE))
    threshold_ood = float(np.quantile(site_ood, SITE_PERCENTILE))

    held_scores = scores_of(held_dataset)
    held_labels = held_dataset.binary_label
    held_embeddings = embeddings_of(held_dataset)
    held_ood = mahalanobis_distances(held_embeddings, ood_center, ood_inverse)

    attack_mask = held_labels == 1
    benign_mask = held_labels == 0
    by_family: dict[str, object] = {}
    for family in sorted(set(held_dataset.family)):
        mask = np.asarray([f == family for f in held_dataset.family]) & attack_mask
        if not mask.any():
            continue
        attack_flags = held_scores[mask] >= threshold_score
        ood_flags = held_ood[mask] >= threshold_ood
        low_rows = sum(
            1
            for observability, keep in zip(held_dataset.observability, mask, strict=True)
            if keep and observability == "LOW"
        )
        by_family[family] = {
            "rows": int(mask.sum()),
            "known_channel_recall": round(float(attack_flags.mean()), 5),
            "ood_channel_recall": round(float(ood_flags.mean()), 5),
            "detection_or_review": round(
                float((attack_flags | ood_flags).mean()),
                5,
            ),
            "low_observability_fraction": round(
                float(low_rows / max(int(mask.sum()), 1)), 5
            ),
        }
    return {
        "rotation": name,
        "held_scenarios": sorted(held_scenarios),
        "held_family": held_family,
        "site_benign_scenario": site_benign_scenario,
        "benign_test_scenario": benign_test_scenario,
        "fit_counts": {
            "benign": int((fit_dataset.binary_label == 0).sum()),
            "malicious": int((fit_dataset.binary_label == 1).sum()),
            "fit_families": sorted({str(f) for f in fit_dataset.family}),
        },
        "thresholds": {
            "known_channel_site_p99": round(threshold_score, 6),
            "ood_channel_site_p99": round(threshold_ood, 5),
        },
        "held_family_channels": by_family,
        "independent_benign_test": {
            "rows": int(benign_mask.sum()),
            "known_channel_fpr": round(
                float((held_scores[benign_mask] >= threshold_score).mean()), 5
            )
            if benign_mask.any()
            else 0.0,
            "ood_channel_fpr": round(
                float((held_ood[benign_mask] >= threshold_ood).mean()), 5
            )
            if benign_mask.any()
            else 0.0,
            "combined_channel_fpr": float(
                ((held_scores[benign_mask] >= threshold_score)
                 | (held_ood[benign_mask] >= threshold_ood)).mean()
            ),
        },
    }


def main() -> None:
    sequence_dir = Path("data/sequences_v2")
    # Corrected runs stay local until full run provenance has been reviewed and
    # registered. Never overwrite the retained historical DEV2-FAMILY-001 record.
    output_dir = Path("data/research_v2_corrected")
    report_path = output_dir / "dev2-strict-held-family-v2.json"
    if report_path.exists():
        raise ValueError(f"refusing to overwrite experiment evidence: {report_path}")
    paths = sorted(sequence_dir.glob("*.jsonl"))
    records = deduplicate_records(load_records(paths))

    s_mirai = "CTU-IoT-Malware-Capture-34-1"
    s_hakai = "CTU-IoT-Malware-Capture-8-1"
    hp4 = "CTU-Honeypot-Capture-4-1"
    hp5 = "CTU-Honeypot-Capture-5-1"
    torii_benign = "CTU-IoT-Malware-Capture-42-1"

    rotations = {
        "HF1_hold_all_c_and_c": {
            "fit_scenarios": {s_mirai, torii_benign},
            "fit_families": {"ddos", "port_scan", "benign"},
            "held_family": "c_and_c",
            "held_scenarios": {s_mirai, s_hakai},
            "site_benign_scenario": hp4,
            "benign_test_scenario": hp5,
        },
        "HF2_hold_all_ddos": {
            "fit_scenarios": {s_mirai, s_hakai, torii_benign},
            "fit_families": {"c_and_c", "port_scan", "benign"},
            "held_family": "ddos",
            "held_scenarios": {s_mirai},
            "site_benign_scenario": hp4,
            "benign_test_scenario": hp5,
        },
        "HF3_hold_all_port_scan": {
            "fit_scenarios": {s_mirai, s_hakai, torii_benign},
            "fit_families": {"c_and_c", "ddos", "benign"},
            "held_family": "port_scan",
            "held_scenarios": {s_mirai},
            "site_benign_scenario": hp4,
            "benign_test_scenario": hp5,
        },
    }

    report = {
        "schema_version": "1.0.0",
        "experiment_id": "DEV2-FAMILY-002",
        "generated_at": datetime.now(UTC).isoformat(),
        "seed": SEED,
        "epochs": 150,
        "batch_size": BATCH_SIZE,
        "learning_rate": LEARNING_RATE,
        "site_percentile": SITE_PERCENTILE,
        "protocol_note": (
            "Held families are absent from fitting. Both channels are calibrated only "
            "on approved target-site benign scores at the 99th percentile."
        ),
        "status": "development_evidence_only_no_candidate_selected",
        "registration_status": "unregistered_diagnostic_not_selection_evidence",
    }
    rotation_results: dict[str, object] = {}
    for name, config in rotations.items():
        print(f"running {name} ...", flush=True)
        rotation_results[name] = run_rotation(
            name,
            set(config["fit_scenarios"]),
            set(config["fit_families"]),
            str(config["held_family"]),
            set(config["held_scenarios"]),
            str(config["site_benign_scenario"]),
            str(config["benign_test_scenario"]),
            records,
        )
        print(json.dumps(rotation_results[name], indent=2, sort_keys=True), flush=True)
    report["rotations"] = rotation_results
    output_dir.mkdir(parents=True, exist_ok=True)
    with report_path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"wrote {report_path}")


if __name__ == "__main__":
    main()
