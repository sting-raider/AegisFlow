from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from scripts.verify_registered_research_v2 import render_summary, validate_report, verify
from training.v2.provenance import read_object

ROOT = Path(__file__).resolve().parents[2]
REPORT = "docs/research-v2/registered-results/DEV2-FAMILY-002.json"


def test_published_registered_family_evidence_is_bound() -> None:
    report = verify(ROOT)
    assert len(report["rotations"]) == 6
    assert (ROOT / REPORT).with_suffix(".md").read_text(encoding="utf-8") == render_summary(report)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_rotation",
        "known_as_unknown",
        "site_in_fit",
        "missing_memory",
        "raw_ids",
        "unbound_preparation",
    ],
)
def test_semantic_evidence_mutations_fail_even_without_file_hash_check(mutation: str) -> None:
    report = deepcopy(read_object(ROOT / REPORT))
    first = report["rotations"][0]
    if mutation == "missing_rotation":
        report["rotations"].pop()
    elif mutation == "known_as_unknown":
        first["test"]["attack"]["direct_suspicious_unknown"]["count"] = 1
    elif mutation == "site_in_fit":
        first["partition_provenance"]["fit"]["scenarios"].append(
            first["site_orientation"]["calibration"]
        )
    elif mutation == "missing_memory":
        first["memory"]["sampled_peak_rss_bytes"] = 0
    elif mutation == "raw_ids":
        first["event_ids"] = ["private-row"]
    elif mutation == "unbound_preparation":
        report["preparation_manifest"]["preparation_code_commit"] = "0" * 40
    with pytest.raises(ValueError):
        validate_report(ROOT, report)


def test_unreviewed_model_files_are_not_required_for_public_ci_but_missing_local_files_fail(
    tmp_path: Path,
) -> None:
    with pytest.raises((ValueError, FileNotFoundError)):
        verify(ROOT, artifact_directory=tmp_path)
