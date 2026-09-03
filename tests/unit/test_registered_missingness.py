from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any, cast
from unittest.mock import Mock

import numpy as np
import pytest
from sklearn.exceptions import ConvergenceWarning

from training.v2 import registered_missingness as runner
from training.v2.missingness import observation_inputs
from training.v2.missingness_model import load_predictor
from training.v2.tensors import SequenceRecord
from training.v2.transfer_support import load_registration

ROOT = Path(__file__).resolve().parents[2]


def config() -> dict[str, Any]:
    result = load_registration(ROOT)
    result["measurement"].update(
        {
            "warmup_calls_per_batch_size": 1,
            "measured_calls_per_batch_size": 2,
            "batch_sizes": [1, 4],
        }
    )
    return result


def partitions() -> dict[str, list[SequenceRecord]]:
    generator = np.random.default_rng(789)
    result = {}
    roles = {
        "fit": ("train", 40),
        "site_calibration": ("hp4", 10),
        "benign_test": ("hp5", 12),
        "target": ("target", 16),
    }
    for role, (scenario, count) in roles.items():
        records = []
        for index in range(count):
            malicious = role in {"fit", "target"} and index % 2 == 1
            packets = generator.integers(2, 40, 2)
            byte_counts = generator.integers(100, 50000, 2)
            records.append(
                cast(
                    SequenceRecord,
                    {
                        "event_id": f"{scenario}-{index}",
                        "scenario": scenario,
                        "family": ("c_and_c" if role == "fit" else "other_attack")
                        if malicious
                        else "benign",
                        "binary_label": "malicious" if malicious else "benign",
                        "duration_ms": float(generator.uniform(1, 1000)),
                        "packets_forward": int(packets[0]),
                        "packets_reverse": int(packets[1]),
                        "bytes_forward": int(byte_counts[0]),
                        "bytes_reverse": int(byte_counts[1]),
                        "seq_sizes": [float(generator.uniform(20, 1000)) for _ in range(3)],
                        "seq_directions": [1, -1, 1],
                        "seq_iats_ms": [0.0, 1.0, 2.0],
                        "dst_port": 80,
                        "protocol": "TCP",
                    },
                )
            )
        result[role] = records
    return result


def execute(output: Path, **overrides: Any) -> dict[str, Any]:
    return runner.run_case(
        partitions(),
        config(),
        case_id="fixture",
        target="target",
        sources=["train"],
        view="portable_intersection",
        kind="standard",
        output=output,
        **overrides,
    )


def test_registered_case_preserves_both_sites_costs_metrics_and_numeric_artifact(
    tmp_path: Path,
) -> None:
    result = execute(tmp_path)
    assert result["status"] == "evaluated"
    assert result["fit_attempted"]
    assert result["fit_seconds"] > 0
    assert result["feature_build_seconds"] > 0
    assert result["memory"]["sampled_peak_rss_bytes"] > 0
    assert len(list(tmp_path.glob("*.npz"))) == 1
    first, second = result["site_evaluations"]
    assert first["partition_provenance"]["site_calibration"]["rows"] == 10
    assert second["partition_provenance"]["site_calibration"]["rows"] == 12
    assert first["partition_provenance"]["target"] == second["partition_provenance"]["target"]
    for site in (first, second):
        assert not site["target_families"]["other_attack"]["present_in_supervised_fit"]
        assert site["target"]["benign"]["rows"] == 8
        assert site["target"]["attack"]["rows"] == 8
        assert np.asarray(site["confusion_matrix"]).sum() == site["combined"]["rows"]
        assert site["calibration"]["benign"]["direct_union_fpr"]["rate"] <= 0.01
        assert [batch["batch_size"] for batch in site["inference"]] == [1, 4]
        assert all(batch["measured_calls"] == 2 for batch in site["inference"])
    model = load_predictor(tmp_path / "fixture.npz", result["artifact"], config())
    scores, distances = model.score_inputs(observation_inputs(partitions()["target"]))
    assert scores.shape == distances.shape == (16,)
    assert np.isfinite(scores).all() and np.isfinite(distances).all()
    assert runner.verify_artifacts(tmp_path, [result], config()) == 1


def test_nonconverging_case_retains_failure_costs_and_does_not_fabricate_sites(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory = Mock()
    factory.return_value.fit.side_effect = ConvergenceWarning("controlled convergence failure")
    monkeypatch.setattr(runner, "LogisticRegression", factory)
    result = execute(tmp_path)
    assert result["status"] == "ineligible"
    assert result["failure_phase"] == "linear_fit"
    assert result["fit_attempted"]
    assert result["fit_seconds"] > 0
    assert result["memory"]["rss_after_bytes"] > 0
    assert "artifact" not in result
    assert all(
        site["status"] == "ineligible_model" and "target" not in site
        for site in result["site_evaluations"]
    )
    assert runner.verify_artifacts(tmp_path, [result], config()) == 0


def test_post_transform_alias_rejects_before_any_linear_fit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        runner.MissingnessTransform,
        "transform",
        lambda self, batch: np.zeros((len(batch.values), 9)),
    )
    factory = Mock()
    monkeypatch.setattr(runner, "LogisticRegression", factory)
    result = execute(tmp_path)
    assert result["status"] == "ineligible"
    assert result["failure_phase"] == "preprocessing"
    assert not result["fit_attempted"]
    assert result["fit_seconds"] > 0
    assert "alias" in result["reason"]
    assert result["transformed_inputs"]["fit"]["distinct_inputs"] == 1
    factory.assert_not_called()


@pytest.mark.parametrize("phase", ["site_evaluation", "artifact_roundtrip"])
def test_scoring_and_artifact_failures_stop_instead_of_becoming_model_results(
    phase: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if phase == "site_evaluation":
        monkeypatch.setattr(runner, "site_metrics", Mock(side_effect=FloatingPointError("fixture")))
        exception = FloatingPointError
    else:
        monkeypatch.setattr(runner, "load_predictor", Mock(side_effect=ValueError("fixture")))
        exception = ValueError
    with pytest.raises(exception, match="fixture"):
        execute(tmp_path)


def test_missingness_existing_output_is_refused_before_code_or_input_access(tmp_path: Path) -> None:
    with pytest.raises(FileExistsError, match="reuse"):
        runner.run(tmp_path / "missing.json", tmp_path / "absent", tmp_path)


def test_numeric_artifact_tampering_and_unbound_files_are_rejected(tmp_path: Path) -> None:
    result = execute(tmp_path)
    metadata = deepcopy(result["artifact"])
    metadata["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="hash"):
        load_predictor(tmp_path / "fixture.npz", metadata, config())
    np.savez(tmp_path / "unbound.npz", extra=np.zeros(1))
    with pytest.raises(ValueError, match="unbound"):
        runner.verify_artifacts(tmp_path, [result], config())


def test_cohort_binding_checks_every_registered_count_and_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = config()
    mock_report = {
        "input_core_groups": cfg["cohort"]["core_groups"],
        "cross_capture_groups": cfg["cohort"]["cross_capture_groups"],
        "groups_with_optional_packet_variants": cfg["cohort"][
            "groups_with_optional_packet_variants"
        ],
        "cross_capture_excluded": {"rows": 284},
        "within_capture_ambiguous_excluded": {"rows": 249},
        "within_capture_duplicate_rows": {"rows": 417},
        "retained": {
            "event_ids_sha256": cfg["cohort"]["retained_event_ids_sha256"],
            "records_sha256": "changed",
        },
    }
    monkeypatch.setattr(runner, "common_support", lambda _: ([{}] * 6195, mock_report))
    with pytest.raises(ValueError, match="cohort differs"):
        runner.admit_cohort([cast(SequenceRecord, {})] * 7145, cfg)


def test_paired_source_comparisons_account_for_missing_results(tmp_path: Path) -> None:
    fixture = execute(tmp_path)
    cfg = config()
    results = []
    for number, (target, sources) in enumerate(runner.matrix_choices(cfg)):
        for view in cfg["representation"]["views"]:
            for kind in cfg["representation"]["transforms"]:
                entry = deepcopy(fixture)
                entry.update(
                    {
                        "case_id": f"{number}-{view}-{kind}",
                        "target_capture": target,
                        "fit_sources": sources,
                        "view": view,
                        "transform": kind,
                    }
                )
                results.append(entry)
    assert len(results) == 108
    comparisons = runner.paired_comparisons(results, cfg)
    assert len(comparisons) == 72
    assert all(item["status"] == "paired" for item in comparisons)
    assert all(
        value == 0
        for item in comparisons
        for delta in item["combined_minus_single"]
        for value in delta.values()
    )
    results[0]["status"] = "ineligible"
    comparisons = runner.paired_comparisons(results, cfg)
    assert sum(item["status"] == "unpaired_ineligible_entries" for item in comparisons) == 2
    assert all(
        "combined" not in item
        for item in comparisons
        if item["status"] == "unpaired_ineligible_entries"
    )
    with pytest.raises(ValueError, match="three choices"):
        runner.paired_comparisons(results[1:], cfg)


@pytest.mark.parametrize("change_inputs_at_end", [False, True])
def test_complete_runner_retains_every_case_and_rechecks_inputs(
    change_inputs_at_end: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = config()
    cfg["experiment_id"] = "synthetic-runner-fixture"
    cfg["representation"]["views"] = ["portable_intersection"]
    cfg["representation"]["transforms"] = ["standard"]
    cfg["splits"]["expected_model_fits"] = 9
    cfg["splits"]["expected_site_evaluations"] = 18
    source_rows = partitions()
    raw = []
    for index, scenario in enumerate(cfg["splits"]["attack_environments"]):
        for item in source_rows["fit"][index * 10 : (index + 1) * 10]:
            raw.append({**item, "scenario": scenario})
    for item in source_rows["fit"][30:]:
        raw.append(
            {
                **item,
                "scenario": cfg["splits"]["background_benign"],
                "family": "benign",
                "binary_label": "benign",
            }
        )
    for role, field in (("site_calibration", "calibration"), ("benign_test", "benign_test")):
        for item in source_rows[role]:
            raw.append({**item, "scenario": cfg["splits"]["site_orientations"][0][field]})
    later = deepcopy(raw)
    if change_inputs_at_end:
        later[0]["duration_ms"] += 1
    load = Mock(side_effect=[raw, later])
    source_check = Mock()
    monkeypatch.setattr(runner, "load_registration", lambda _: cfg)
    monkeypatch.setattr(runner, "clean_execution_commit", lambda _: "a" * 40)
    monkeypatch.setattr(runner, "verify_capture_pool", source_check)
    monkeypatch.setattr(runner, "load_verified_preparation", load)
    monkeypatch.setattr(runner, "admit_cohort", lambda _raw, _cfg: (raw, {"limitations": []}))
    output = tmp_path / "run"
    manifest = ROOT / cfg["prepared_manifest"]["path"]
    if change_inputs_at_end:
        with pytest.raises(ValueError, match="changed during execution"):
            runner.run(manifest, tmp_path, output)
        assert not (output / "report.json").exists()
    else:
        path = runner.run(manifest, tmp_path, output)
        report = json.loads(path.read_text(encoding="utf-8"))
        assert report["coverage"]["planned_model_entries"] == 9
        assert report["coverage"]["planned_site_entries"] == 18
        assert report["coverage"]["evaluated_models"] == 9
        assert len(report["cases"]) == 9
        assert len(report["source_addition_comparisons"]) == 6
    assert source_check.call_count == load.call_count == 2
    assert (output / "attempt.json").exists()
    assert len(list(output.glob("choice*.json"))) == 9
