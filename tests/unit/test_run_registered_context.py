from __future__ import annotations

from pathlib import Path

import pytest

from training.v2.context_analysis import matrix_choices
from training.v2.registered_context import load_registration
from training.v2.run_registered_context import verify_artifacts


def test_context_matrix_choices_are_exact_and_capture_disjoint() -> None:
    root = Path(__file__).resolve().parents[2]
    config = load_registration(root)
    choices = matrix_choices(config)

    assert len(choices) == 9
    for target, sources in choices:
        assert target not in sources
        assert 1 <= len(sources) <= 2
        assert len(sources) == len(set(sources))


def test_context_artifact_verifier_rejects_unbound_file(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    config = load_registration(root)
    (tmp_path / "unbound.npz").write_bytes(b"not-an-artifact")

    with pytest.raises(ValueError, match="unbound context model artifact"):
        verify_artifacts(tmp_path, [], config)
