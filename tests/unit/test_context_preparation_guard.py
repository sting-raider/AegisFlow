from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from scripts.verify_context_preparation import (
    MANIFEST_PATH,
    MULTIVIEW_MANIFEST_PATH,
    validate_manifest,
)
from training.v2.provenance import read_object


def test_committed_context_preparation_manifest_is_valid() -> None:
    root = Path(__file__).resolve().parents[2]
    validate_manifest(root, read_object(root / MANIFEST_PATH))


def test_context_preparation_guard_rejects_accounting_mutation() -> None:
    root = Path(__file__).resolve().parents[2]
    manifest = read_object(root / MANIFEST_PATH)
    mutated = deepcopy(manifest)
    mutated["scenarios"][0]["context_only_flows"] += 1

    with pytest.raises(ValueError, match="history-flow accounting mismatch"):
        validate_manifest(root, mutated)


def test_committed_multiview_context_manifest_is_valid() -> None:
    root = Path(__file__).resolve().parents[2]
    validate_manifest(
        root,
        read_object(root / MULTIVIEW_MANIFEST_PATH),
        multiview=True,
    )


def test_multiview_guard_rejects_terminal_count_mutation() -> None:
    root = Path(__file__).resolve().parents[2]
    manifest = read_object(root / MULTIVIEW_MANIFEST_PATH)
    mutated = deepcopy(manifest)
    mutated["scenarios"][0]["non_causal_late_rows"] += 1

    with pytest.raises(ValueError, match="preparation totals disagree"):
        validate_manifest(root, mutated, multiview=True)
