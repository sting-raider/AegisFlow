from __future__ import annotations

import json
import sys
from dataclasses import replace
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from packages.features.registry import FEATURE_NAMES
from packages.features.research import PORTABLE_FEATURE_NAMES, RUNTIME_ENRICHED_FEATURE_NAMES
from packages.model_bundle import ModelBundle
from training.cli.evaluate_dataset import main as evaluate_dataset_main
from training.data.adapters import load_dataset
from training.data.evaluate import evaluate_logistic_gate
from training.data.hybrid_evaluate import evaluate_hybrid_gate
from training.data.models import CanonicalDataset, InputProvenance
from training.data.quality import feature_drift, quality_report, train_test_overlap
from training.data.splits import create_split


def _cic_frame() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "Flow Duration": [1_000, 2_000, 3_000],
            "Total Fwd Packets": [2, 20, 5],
            "Total Backward Packets": [1, 1, 2],
            "Total Length of Fwd Packets": [200, 2_000, 500],
            "Total Length of Bwd Packets": [100, 20, 200],
            "Flow Packets/s": [3_000, 10_500, 2_333],
            "Flow Bytes/s": [300_000, 1_010_000, 233_333],
            "Packet Length Mean": [100, 96, 100],
            "Packet Length Std": [10, 30, 15],
            "Flow IAT Mean": [500, 100, 600],
            "Flow IAT Std": [50, 20, 60],
            "SYN Flag Count": [1, 20, 2],
            "RST Flag Count": [0, 3, 0],
            "Destination Port": [443, 22, 80],
            "Timestamp": [
                "03/07/2017 09:00:00",
                "04/07/2017 09:00:00",
                "05/07/2017 09:00:00",
            ],
            "Source IP": ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
            "Label": ["BENIGN", "DoS Hulk", "FTP-Patator"],
        }
    )


def test_cic_adapter_maps_units_labels_and_drops_identifiers(tmp_path: Path) -> None:
    path = tmp_path / "day.csv"
    _cic_frame().to_csv(path, index=False)
    dataset = load_dataset("cic_ids2017", [path])
    assert dataset.features.shape == (3, len(FEATURE_NAMES))
    assert dataset.features[0, FEATURE_NAMES.index("duration_ms")] == 1.0
    assert dataset.labels.tolist() == ["benign", "dos", "brute_force"]
    report = quality_report(dataset)
    assert "Source IP" in report.identifier_columns
    assert "Source IP" not in FEATURE_NAMES
    assert dataset.portable_features is not None
    assert dataset.portable_features.shape == (3, len(PORTABLE_FEATURE_NAMES))
    assert dataset.runtime_enriched_features is None


def test_cic_adapter_replays_shared_temporal_features_when_endpoints_and_time_exist(
    tmp_path: Path,
) -> None:
    frame = _cic_frame().copy()
    frame["Destination IP"] = ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
    path = tmp_path / "temporal.csv"
    frame.to_csv(path, index=False)

    dataset = load_dataset("cic_ids2017", [path])

    assert dataset.runtime_enriched_features is not None
    assert dataset.runtime_enriched_features.shape == (
        3,
        len(RUNTIME_ENRICHED_FEATURE_NAMES),
    )
    assert any("source-row order" in note for note in dataset.research_feature_notes)


def test_cse_and_generic_nfstream_adapters_are_registered(tmp_path: Path) -> None:
    cse_path = tmp_path / "cse.csv"
    _cic_frame().to_csv(cse_path, index=False)
    assert load_dataset("cse_cic_ids2018", [cse_path]).row_count == 3
    generic_path = tmp_path / "nfstream.csv"
    pd.DataFrame(
        {
            "bidirectional_duration_ms": [10, 20],
            "src2dst_packets": [2, 4],
            "dst2src_packets": [1, 2],
            "src2dst_bytes": [200, 400],
            "dst2src_bytes": [100, 200],
            "bidirectional_packets_rate": [300, 300],
            "bidirectional_bytes_rate": [30_000, 30_000],
            "bidirectional_mean_ps": [100, 100],
            "bidirectional_stddev_ps": [0, 0],
            "bidirectional_mean_piat_ms": [5, 5],
            "bidirectional_stddev_piat_ms": [0, 0],
            "bidirectional_syn_packets": [1, 1],
            "bidirectional_rst_packets": [0, 0],
            "dst_port": [443, 22],
            "capture": ["one", "two"],
            "class": ["normal", "port scan"],
        }
    ).to_csv(generic_path, index=False)
    generic = load_dataset(
        "nfstream_csv", [generic_path], label_column="class", group_column="capture"
    )
    assert generic.labels.tolist() == ["benign", "port_scan"]
    assert generic.groups.tolist() == ["one", "two"]


def test_cse_adapter_audits_repeated_headers_and_nonfinite_cic_rows(
    tmp_path: Path,
) -> None:
    frame = _cic_frame().iloc[[0, 1]].copy()
    frame.loc[frame.index[1], "Label"] = "Infilteration"
    repeated_header = pd.DataFrame([{column: column for column in frame.columns}])
    nonfinite = frame.iloc[[0]].copy()
    nonfinite["Flow Packets/s"] = np.inf
    nonfinite["Flow Bytes/s"] = np.inf
    path = tmp_path / "official-cse-shards.csv"
    pd.concat([frame, repeated_header, nonfinite], ignore_index=True).to_csv(path, index=False)

    dataset = load_dataset("cse_cic_ids2018", [path])

    assert dataset.labels.tolist() == ["benign", "infiltration"]
    assert [(item.reason, item.count) for item in dataset.row_exclusions] == [
        ("repeated_csv_header", 1),
        ("nonfinite_or_out_of_registry_canonical_features", 1),
    ]
    report = quality_report(dataset)
    assert report.excluded_rows == (
        {"reason": "repeated_csv_header", "count": 1},
        {"reason": "nonfinite_or_out_of_registry_canonical_features", "count": 1},
    )
    assert not report.blocking_issues


def test_official_dataset_catalog_has_all_supported_adapters() -> None:
    catalog = json.loads(Path("configs/datasets/catalog.json").read_text(encoding="utf-8"))
    assert set(catalog["datasets"]) == {
        "cic_ids2017",
        "cse_cic_ids2018",
        "unsw_nb15",
        "nfstream_csv",
        "synthetic_smoke",
    }


def test_quality_flags_predictive_source_columns_and_nonfinite_values(tmp_path: Path) -> None:
    frame = pd.concat([_cic_frame(), _cic_frame()], ignore_index=True)
    frame["Flow Duration"] += np.arange(len(frame))
    frame["Source IP"] = [f"10.0.0.{index}" for index in range(len(frame))]
    frame["Label Leak"] = [0, 1, 2, 0, 1, 2]
    path = tmp_path / "quality.csv"
    frame.to_csv(path, index=False)
    dataset = load_dataset("cic_ids2017", [path])
    report = quality_report(dataset)
    assert any(item["column"] == "Label Leak" for item in report.suspiciously_predictive_columns)
    invalid_values = dataset.features.copy()
    invalid_values[0, 0] = np.nan
    invalid_values[1, 1] = np.inf
    invalid_values[2, FEATURE_NAMES.index("destination_port")] = 70_000
    invalid = replace(dataset, features=invalid_values)
    invalid_report = quality_report(invalid)
    assert sum(invalid_report.missing_values.values()) == 1
    assert sum(invalid_report.infinite_values.values()) == 1
    assert sum(invalid_report.out_of_range_values.values()) >= 1
    assert len(invalid_report.blocking_issues) == 3


def test_unsw_adapter_documents_unavailable_fields(tmp_path: Path) -> None:
    path = tmp_path / "unsw.csv"
    pd.DataFrame(
        {
            "dur": [0.2, 0.5],
            "spkts": [2, 8],
            "dpkts": [1, 2],
            "sbytes": [200, 800],
            "dbytes": [100, 200],
            "rate": [15, 20],
            "sload": [800, 1600],
            "dload": [400, 800],
            "smean": [100, 100],
            "dmean": [100, 100],
            "sinpkt": [5, 7],
            "dinpkt": [5, 7],
            "dsport": [53, 443],
            "attack_cat": ["Normal", "Exploits"],
            "label": [0, 1],
        }
    ).to_csv(path, index=False)
    dataset = load_dataset("unsw_nb15", [path])
    assert dataset.labels.tolist() == ["benign", "exploits"]
    assert dataset.features[:, FEATURE_NAMES.index("byte_rate")].tolist() == [150.0, 300.0]
    assert any("tcp_syn_count=0" in note for note in dataset.adapter_notes)


def test_official_unsw_partition_without_ports_is_explicitly_approximated(
    tmp_path: Path,
) -> None:
    path = tmp_path / "official-partition.csv"
    pd.DataFrame(
        {
            "id": [1, 2],
            "dur": [0.2, 0.5],
            "spkts": [2, 8],
            "dpkts": [1, 2],
            "sbytes": [200, 800],
            "dbytes": [100, 200],
            "rate": [15, 20],
            "smean": [100, 100],
            "dmean": [100, 100],
            "sinpkt": [5, 7],
            "dinpkt": [5, 7],
            "attack_cat": ["Normal", "Exploits"],
            "label": [0, 1],
        }
    ).to_csv(path, index=False)
    dataset = load_dataset("unsw_nb15", [path])
    destination_port = FEATURE_NAMES.index("destination_port")
    assert dataset.features[:, destination_port].tolist() == [0.0, 0.0]
    assert any("official UNSW" in note for note in dataset.adapter_notes)
    assert next(
        profile for profile in dataset.source_profiles if profile.name == "id"
    ).identifier_like


def test_manifest_checksum_is_enforced(tmp_path: Path) -> None:
    path = tmp_path / "flows.csv"
    _cic_frame().to_csv(path, index=False)
    path.with_suffix(".csv.manifest.json").write_text(
        json.dumps({"sha256": "0" * 64}), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="checksum"):
        load_dataset("cic_ids2017", [path])


def _canonical(seed: int = 7, name: str = "fixture") -> CanonicalDataset:
    rng = np.random.default_rng(seed)
    rows: list[np.ndarray] = []
    labels: list[str] = []
    groups: list[str] = []
    timestamps: list[np.datetime64] = []
    for group in range(6):
        for label, offset in (("benign", 0.0), ("dos", 4.0), ("brute_force", 8.0)):
            for item in range(8):
                rows.append(np.abs(rng.normal(offset + 2.0, 0.4, len(FEATURE_NAMES))))
                labels.append(label)
                groups.append(f"capture-{group}")
                timestamps.append(
                    np.datetime64("2026-01-01") + np.timedelta64(group * 24 + item, "h")
                )
    values = np.vstack(rows)
    values[:, FEATURE_NAMES.index("destination_port")] = np.clip(
        values[:, FEATURE_NAMES.index("destination_port")] * 1000, 0, 65_535
    )
    return CanonicalDataset(
        name=name,
        features=values,
        labels=np.asarray(labels),
        raw_labels=np.asarray(labels),
        groups=np.asarray(groups),
        timestamps=np.asarray(timestamps, dtype="datetime64[ns]"),
        source_files=np.asarray(groups),
        raw_column_names=FEATURE_NAMES,
        source_profiles=(),
        provenance=(InputProvenance(f"{name}.csv", 1, f"{seed:064x}", None),),
    )


def test_group_time_and_family_splits_are_disjoint() -> None:
    dataset = _canonical()
    grouped = create_split(dataset, "source_file")
    assert grouped.group_overlap == 0
    timed = create_split(dataset, "time")
    assert (
        dataset.timestamps[timed.train_indices].max()
        <= dataset.timestamps[timed.test_indices].min()
    )
    family = create_split(dataset, "leave_family_out", held_out_family="dos")
    assert set(dataset.labels[family.test_indices]) == {"dos"}
    assert "dos" not in set(dataset.labels[family.train_indices])


def test_quality_overlap_drift_and_evaluation_are_reported() -> None:
    training = _canonical()
    testing = _canonical(seed=9, name="other")
    split = create_split(training, "source_file")
    evaluation = evaluate_logistic_gate(training, training, split.train_indices, split.test_indices)
    assert evaluation["macro_f1"] >= 0.0
    assert evaluation["queue_lag"]["measured"] is False
    assert evaluation["latency_ms"]["p95_single"] >= 0.0
    overlap = train_test_overlap(training.features, testing.features)
    assert overlap["overlap_rows"] == 0
    drift = feature_drift(training, testing)
    assert set(drift["features"]) == set(FEATURE_NAMES)
    cross_evaluation = evaluate_logistic_gate(
        training,
        testing,
        np.arange(training.row_count),
        np.arange(testing.row_count),
    )
    assert cross_evaluation["testing_dataset"] == "other"


def test_exact_hybrid_evaluation_uses_all_deployed_signals_and_held_family(
    bundle: ModelBundle,
) -> None:
    dataset = _canonical()
    grouped = create_split(dataset, "source_file")
    grouped_evaluation = evaluate_hybrid_gate(
        dataset,
        dataset,
        grouped.train_indices,
        grouped.test_indices,
        bundle,
    )
    assert grouped_evaluation["harness"] == "exact deployed hybrid pipeline"
    assert grouped_evaluation["shared_inference_path"].endswith("HybridPredictor")
    assert set(grouped_evaluation["verdict_counts"]) == {
        "benign",
        "known_attack",
        "suspicious_unknown",
        "needs_review",
    }
    assert grouped_evaluation["fit_manifest"]["calibration_benign_rows"] >= 2
    assert grouped_evaluation["train_test_overlap"]["overlap_rows"] == 0
    assert grouped_evaluation["macro_f1"] == pytest.approx(
        grouped_evaluation["verdict_classification"]["macro avg"]["f1-score"]
    )
    assert grouped_evaluation["fusion_comparison"]["macro_f1_label_scope"] == [
        "benign",
        "known_attack",
        "suspicious_unknown",
        "needs_review",
    ]
    assert grouped_evaluation["readiness_gate"]["automatic_promotion_allowed"] is False

    held = create_split(dataset, "leave_family_out", held_out_family="dos")
    held_evaluation = evaluate_hybrid_gate(
        dataset,
        dataset,
        held.train_indices,
        held.test_indices,
        bundle,
    )
    assert held_evaluation["unknown_test_families"] == ["dos"]
    assert held_evaluation["suspicious_unknown_detection_rate"] is not None
    assert (
        held_evaluation["readiness_gate"]["criteria"][
            "suspicious_unknown_detection_rate"
        ]["status"]
        in {"pass", "fail"}
    )

    one_source = replace(dataset, groups=np.full(dataset.row_count, "one-source"))
    timed = create_split(one_source, "time")
    timed_evaluation = evaluate_hybrid_gate(
        one_source,
        one_source,
        timed.train_indices,
        timed.test_indices,
        bundle,
    )
    assert timed_evaluation["fit_manifest"]["calibration_split"]["method"].startswith(
        "chronological calibration"
    )


def test_dataset_evaluation_cli_writes_a_complete_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths: list[Path] = []
    for capture in range(2):
        frame = pd.concat([_cic_frame()] * 10, ignore_index=True)
        frame["Flow Duration"] += np.arange(len(frame)) + capture * 100
        path = tmp_path / f"capture-{capture}.csv"
        frame.to_csv(path, index=False)
        paths.append(path)
    output = tmp_path / "evaluation.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "evaluate-dataset",
            "--dataset",
            "cic_ids2017",
            "--input",
            str(paths[0]),
            "--input",
            str(paths[1]),
            "--split",
            "source_file",
            "--output",
            str(output),
        ],
    )
    evaluate_dataset_main()
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["schema_version"] == "1.1.0"
    assert report["split"]["group_overlap"] == 0
    assert "train_indices" not in report["split"]
    assert report["evaluation"]["harness"] == "exact deployed hybrid pipeline"
    assert report["evaluation_bundle"]["bundle_schema_version"] == 3
    assert len(report["evaluation_bundle"]["bundle_digest"]) == 64
    assert report["evaluation"]["feature_order"] == list(FEATURE_NAMES)
    assert report["quality"]["rows"] == 60
