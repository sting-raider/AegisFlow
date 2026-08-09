from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from apps.api.database import Repository
from packages.model_bundle import BundleError, assess_candidate, revalidate_candidate
from packages.model_bundle.bundle import sha256_file


def test_exact_hybrid_evidence_is_bound_to_candidate_and_requires_every_mode(
    registry: Path, tmp_path: Path
) -> None:
    candidate_registry, version = _candidate_bundle(registry, tmp_path)
    reports = tmp_path / "reports"
    names = _passing_reports(reports, candidate_registry, version)
    assessment = assess_candidate(
        candidate_registry,
        reports,
        "aegisflow-smoke",
        version,
        names,
    )
    assert assessment.eligible_for_review
    assert not assessment.blockers
    assert {mode for item in assessment.evidence for mode in item.covered_modes} >= {
        "grouped",
        "time",
        "source_file",
        "leave_family_out",
        "cross_dataset",
    }
    stored = assessment.as_dict()
    assert revalidate_candidate(candidate_registry, reports, stored) == assessment

    report = reports / names[0]
    payload = json.loads(report.read_text(encoding="utf-8"))
    payload["evaluation"]["readiness_gate"]["status"] = "fail"
    payload["evaluation"]["readiness_gate"]["criteria"]["macro_f1"]["status"] = "fail"
    report.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(BundleError, match="changed after review"):
        revalidate_candidate(candidate_registry, reports, stored)


def test_failed_reports_and_synthetic_bundle_can_only_reject(
    registry: Path, tmp_path: Path
) -> None:
    bundle = registry / "aegisflow-smoke" / "0.3.0"
    reports = tmp_path / "reports"
    names = _passing_reports(reports, registry, "0.3.0")
    payload = json.loads((reports / names[0]).read_text(encoding="utf-8"))
    payload["evaluation"]["readiness_gate"]["status"] = "fail"
    payload["evaluation"]["readiness_gate"]["criteria"]["macro_f1"]["status"] = "fail"
    (reports / names[0]).write_text(json.dumps(payload), encoding="utf-8")
    assessment = assess_candidate(
        registry,
        reports,
        "aegisflow-smoke",
        bundle.name,
        names,
    )
    assert not assessment.eligible_for_review
    assert "synthetic_training_bundle" in assessment.blockers
    assert f"report_gate_failed:{names[0]}" in assessment.blockers


def test_candidate_paths_and_gate_criteria_are_strictly_validated(
    registry: Path, tmp_path: Path
) -> None:
    reports = tmp_path / "reports"
    names = _passing_reports(reports, registry, "0.3.0")
    with pytest.raises(BundleError, match="invalid model name"):
        assess_candidate(registry, reports, "..", "0.3.0", names)
    with pytest.raises(BundleError, match="invalid model version"):
        assess_candidate(registry, reports, "aegisflow-smoke", "..", names)

    report = reports / names[0]
    payload = json.loads(report.read_text(encoding="utf-8"))
    payload["evaluation_bundle"]["bundle_digest"] = "0" * 64
    report.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(BundleError, match="does not bind to candidate"):
        assess_candidate(registry, reports, "aegisflow-smoke", "0.3.0", names)

    payload["evaluation_bundle"]["bundle_digest"] = sha256_file(
        registry / "aegisflow-smoke" / "0.3.0" / "checksums.sha256"
    )
    payload["evaluation"]["readiness_gate"]["criteria"]["malformed"] = "pass"
    report.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(BundleError, match="criteria are invalid"):
        assess_candidate(registry, reports, "aegisflow-smoke", "0.3.0", names)


def test_candidate_reviews_are_immutable_and_promotion_separates_duties(
    registry: Path, tmp_path: Path
) -> None:
    candidate_registry, version = _candidate_bundle(registry, tmp_path)
    reports = tmp_path / "reports"
    assessment = assess_candidate(
        candidate_registry,
        reports,
        "aegisflow-smoke",
        version,
        _passing_reports(reports, candidate_registry, version),
    )
    repository = Repository(f"sqlite:///{(tmp_path / 'governance.db').as_posix()}")
    repository.create_schema()
    registered = repository.register_model_candidate(assessment.as_dict(), actor="admin-creator")
    assert registered["status"] == "review_pending"
    with pytest.raises(ValueError, match="creator"):
        repository.review_model_candidate(
            registered["id"], actor="admin-creator", decision="approve", comment="self review"
        )
    approved = repository.review_model_candidate(
        registered["id"],
        actor="analyst-reviewer",
        decision="approve",
        comment="fresh evaluation evidence reviewed",
    )
    assert approved["status"] == "approved"
    assert approved["reviews"][0]["actor"] == "analyst-reviewer"
    with pytest.raises(ValueError, match="different identity"):
        repository.begin_model_promotion(registered["id"], actor="analyst-reviewer")
    pending = repository.begin_model_promotion(registered["id"], actor="admin-promoter")
    assert pending["status"] == "promotion_pending"
    assert repository.reconcile_pending_model_promotions(
        active_model_name="aegisflow-smoke",
        active_version=version,
        active_bundle_digest=assessment.bundle_digest,
    ) == 1
    promoted = repository.model_candidate(registered["id"])
    assert promoted is not None
    assert promoted["status"] == "promoted"
    assert repository.reconcile_pending_model_promotions(
        active_model_name="aegisflow-smoke",
        active_version=version,
        active_bundle_digest=assessment.bundle_digest,
    ) == 0
    actions = [item["action"] for item in repository.audit_events(limit=20)]
    assert actions[:4] == [
        "model_promotion_reconciled",
        "model_promotion_started",
        "model_candidate_reviewed",
        "model_candidate_registered",
    ]


def _candidate_bundle(registry: Path, tmp_path: Path) -> tuple[Path, str]:
    target_registry = tmp_path / "registry"
    model_root = target_registry / "aegisflow-smoke"
    version = "0.4.0"
    target = model_root / version
    shutil.copytree(registry / "aegisflow-smoke" / "0.3.0", target)
    manifest_path = target / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["version"] = version
    manifest["dataset_fingerprints"] = ["reviewed-public-fit-" + "a" * 44]
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    files = sorted(path for path in target.iterdir() if path.name != "checksums.sha256")
    (target / "checksums.sha256").write_text(
        "".join(f"{sha256_file(path)}  {path.name}\n" for path in files),
        encoding="utf-8",
        newline="\n",
    )
    return target_registry, version


def _passing_reports(root: Path, registry: Path, version: str) -> list[str]:
    root.mkdir(parents=True, exist_ok=True)
    bundle_digest = sha256_file(
        registry / "aegisflow-smoke" / version / "checksums.sha256"
    )
    modes = ["source_file", "time", "leave_family_out", "cross_dataset"]
    names: list[str] = []
    for index, mode in enumerate(modes):
        name = f"evidence-{mode}.json"
        payload = {
            "schema_version": "1.1.0",
            "dataset": f"fixture-{index}",
            "fingerprint": str(index) * 64,
            "quality": {"blocking_issues": []},
            "evaluation_bundle": {
                "model_name": "aegisflow-smoke",
                "version": version,
                "bundle_schema_version": 3,
                "bundle_digest": bundle_digest,
            },
            "evaluation": {
                "harness": "exact deployed hybrid pipeline",
                "shared_inference_path": "packages.detection.hybrid.HybridPredictor",
                "training_fingerprint": "a" * 64,
                "testing_fingerprint": "b" * 64,
                "readiness_gate": {
                    "status": "pass",
                    "automatic_promotion_allowed": False,
                    "criteria": {
                        "macro_f1": {"status": "pass", "value": 0.8, "threshold": 0.6}
                    },
                },
            },
        }
        if mode == "cross_dataset":
            payload["evaluation_mode"] = mode
        else:
            payload["split"] = {"strategy": mode, "group_overlap": 0}
        (root / name).write_text(json.dumps(payload), encoding="utf-8")
        names.append(name)
    return names
