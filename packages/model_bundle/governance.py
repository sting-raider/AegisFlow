from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from packages.model_bundle.bundle import BundleError, ModelBundle, sha256_file

REQUIRED_EVALUATION_MODES = (
    "grouped",
    "time",
    "source_file",
    "leave_family_out",
    "cross_dataset",
)
_SUPPORTED_MODES = frozenset(
    {
        "capture_day",
        "cross_dataset",
        "grouped",
        "leave_family_out",
        "official_published_partition",
        "source_file",
        "time",
    }
)
_MAX_REPORTS = 20
_MAX_REPORT_BYTES = 8 * 1024 * 1024
_SAFE_MODEL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SAFE_REPORT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.json$")


@dataclass(frozen=True)
class EvaluationEvidence:
    filename: str
    sha256: str
    mode: str
    covered_modes: tuple[str, ...]
    gate_status: str
    training_fingerprint: str | None
    testing_fingerprint: str | None


@dataclass(frozen=True)
class CandidateAssessment:
    model_name: str
    version: str
    bundle_digest: str
    required_modes: tuple[str, ...]
    evidence: tuple[EvaluationEvidence, ...]
    blockers: tuple[str, ...]

    @property
    def eligible_for_review(self) -> bool:
        return not self.blockers

    def as_dict(self) -> dict[str, Any]:
        return {
            "model_name": self.model_name,
            "version": self.version,
            "bundle_digest": self.bundle_digest,
            "required_modes": list(self.required_modes),
            "evidence": [
                {
                    "filename": item.filename,
                    "sha256": item.sha256,
                    "mode": item.mode,
                    "covered_modes": list(item.covered_modes),
                    "gate_status": item.gate_status,
                    "training_fingerprint": item.training_fingerprint,
                    "testing_fingerprint": item.testing_fingerprint,
                }
                for item in self.evidence
            ],
            "blockers": list(self.blockers),
            "eligible_for_review": self.eligible_for_review,
        }


def required_evaluation_modes() -> tuple[str, ...]:
    raw = os.getenv(
        "AEGISFLOW_MODEL_REQUIRED_EVALUATION_MODES",
        ",".join(REQUIRED_EVALUATION_MODES),
    )
    modes = tuple(dict.fromkeys(item.strip() for item in raw.split(",") if item.strip()))
    if not modes or any(mode not in _SUPPORTED_MODES for mode in modes):
        raise BundleError("invalid required model evaluation modes")
    return modes


def assess_candidate(
    registry: Path,
    evaluation_root: Path,
    model_name: str,
    version: str,
    report_names: list[str],
    *,
    required_modes: tuple[str, ...] | None = None,
) -> CandidateAssessment:
    if not _SAFE_MODEL_NAME.fullmatch(model_name):
        raise BundleError("invalid model name")
    if not _SAFE_VERSION.fullmatch(version):
        raise BundleError("invalid model version")
    if not report_names or len(report_names) > _MAX_REPORTS:
        raise BundleError("between 1 and 20 evaluation reports are required")
    if len(report_names) != len(set(report_names)):
        raise BundleError("evaluation report names must be unique")

    bundle = ModelBundle.load(registry / model_name / version)
    if str(bundle.manifest.get("model_name")) != model_name:
        raise BundleError("bundle model name does not match candidate")
    modes = required_modes or required_evaluation_modes()
    if any(mode not in _SUPPORTED_MODES for mode in modes):
        raise BundleError("unsupported required evaluation mode")

    evidence = tuple(
        _load_evidence(evaluation_root, name, bundle) for name in sorted(report_names)
    )
    covered = {mode for item in evidence for mode in item.covered_modes}
    blockers = [
        f"report_gate_failed:{item.filename}" for item in evidence if item.gate_status != "pass"
    ]
    missing = sorted(set(modes) - covered)
    if missing:
        blockers.append(f"missing_evaluation_modes:{','.join(missing)}")
    fingerprints = bundle.manifest.get("dataset_fingerprints")
    if not isinstance(fingerprints, list) or not fingerprints:
        blockers.append("bundle_missing_training_fingerprints")
    elif any(str(value).lower().startswith("synthetic") for value in fingerprints):
        blockers.append("synthetic_training_bundle")
    if int(bundle.manifest.get("bundle_schema_version", 0)) < 3:
        blockers.append("bundle_schema_precedes_empirical_calibration")

    return CandidateAssessment(
        model_name=model_name,
        version=version,
        bundle_digest=sha256_file(bundle.root / "checksums.sha256"),
        required_modes=modes,
        evidence=evidence,
        blockers=tuple(blockers),
    )


def revalidate_candidate(
    registry: Path,
    evaluation_root: Path,
    candidate: dict[str, Any],
) -> CandidateAssessment:
    evidence = candidate.get("evidence")
    required_modes = candidate.get("required_modes")
    if not isinstance(evidence, list) or not isinstance(required_modes, list):
        raise BundleError("stored candidate evidence is invalid")
    report_names = [
        str(item.get("filename")) for item in evidence if isinstance(item, dict)
    ]
    if len(report_names) != len(evidence):
        raise BundleError("stored candidate report list is invalid")
    assessment = assess_candidate(
        registry,
        evaluation_root,
        str(candidate.get("model_name", "")),
        str(candidate.get("version", "")),
        report_names,
        required_modes=tuple(str(item) for item in required_modes),
    )
    if (
        assessment.bundle_digest != candidate.get("bundle_digest")
        or assessment.as_dict()["evidence"] != evidence
        or assessment.blockers
    ):
        raise BundleError("candidate bundle or evaluation evidence changed after review")
    return assessment


def _load_evidence(
    evaluation_root: Path,
    report_name: str,
    bundle: ModelBundle,
) -> EvaluationEvidence:
    if not _SAFE_REPORT_NAME.fullmatch(report_name) or len(report_name) > 200:
        raise BundleError("invalid evaluation report name")
    path = evaluation_root / report_name
    try:
        if not path.is_file() or path.stat().st_size > _MAX_REPORT_BYTES:
            raise ValueError("report is absent or too large")
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise BundleError(f"invalid evaluation report: {report_name}") from exc
    if not isinstance(payload, dict) or not str(payload.get("schema_version", "")).startswith(
        "1.1."
    ):
        raise BundleError(f"unsupported evaluation report schema: {report_name}")
    binding = payload.get("evaluation_bundle")
    actual_bundle_digest = sha256_file(bundle.root / "checksums.sha256")
    if not isinstance(binding, dict) or (
        binding.get("model_name") != bundle.manifest.get("model_name")
        or binding.get("version") != bundle.version
        or binding.get("bundle_schema_version") != bundle.manifest.get("bundle_schema_version")
        or (
            binding.get("bundle_digest") is not None
            and binding.get("bundle_digest") != actual_bundle_digest
        )
    ):
        raise BundleError(f"evaluation report does not bind to candidate: {report_name}")

    evaluation = payload.get("evaluation")
    if not isinstance(evaluation, dict) or (
        evaluation.get("harness") != "exact deployed hybrid pipeline"
        or evaluation.get("shared_inference_path")
        != "packages.detection.hybrid.HybridPredictor"
    ):
        raise BundleError(f"evaluation report does not use the deployed hybrid path: {report_name}")
    gate = evaluation.get("readiness_gate") if isinstance(evaluation, dict) else None
    if not isinstance(gate, dict):
        gate_status = "blocked"
    else:
        gate_status = str(gate.get("status", "blocked"))
        if gate.get("automatic_promotion_allowed") is not False:
            raise BundleError(f"evaluation report violates manual-promotion policy: {report_name}")
        criteria = gate.get("criteria")
        if not isinstance(criteria, dict) or not criteria:
            raise BundleError(f"evaluation report gate criteria are missing: {report_name}")
        if any(not isinstance(item, dict) for item in criteria.values()):
            raise BundleError(f"evaluation report criteria are invalid: {report_name}")
        statuses = {item.get("status") for item in criteria.values()}
        if not statuses <= {"pass", "fail", "not_applicable"}:
            raise BundleError(f"evaluation report criteria are invalid: {report_name}")
        if gate_status == "pass" and ("fail" in statuses or "pass" not in statuses):
            raise BundleError(f"evaluation report pass status is inconsistent: {report_name}")
    if gate_status not in {"pass", "fail", "blocked"}:
        raise BundleError(f"evaluation report gate status is invalid: {report_name}")
    if gate_status == "pass" and binding.get("bundle_digest") != actual_bundle_digest:
        raise BundleError(f"passing report does not bind exact bundle bytes: {report_name}")

    split = payload.get("split")
    mode_value = payload.get("evaluation_mode")
    if not isinstance(mode_value, str) and isinstance(split, dict):
        mode_value = split.get("strategy")
    if not isinstance(mode_value, str) or mode_value not in _SUPPORTED_MODES:
        raise BundleError(f"evaluation report mode is invalid: {report_name}")
    covered_modes = {mode_value}
    if mode_value in {"source_file", "capture_day"}:
        covered_modes.add("grouped")

    return EvaluationEvidence(
        filename=report_name,
        sha256=sha256_file(path),
        mode=mode_value,
        covered_modes=tuple(sorted(covered_modes)),
        gate_status=gate_status,
        training_fingerprint=_required_digest(evaluation, "training_fingerprint", report_name),
        testing_fingerprint=_required_digest(evaluation, "testing_fingerprint", report_name),
    )


def _required_digest(payload: object, key: str, report_name: str) -> str:
    value = payload.get(key) if isinstance(payload, dict) else None
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise BundleError(f"evaluation report fingerprint is invalid: {report_name}")
    return value
