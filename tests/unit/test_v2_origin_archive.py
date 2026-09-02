from __future__ import annotations

import pytest

from training.v2 import run_origin_diagnostic


def test_legacy_origin_refuses_archive_before_loading_or_training(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_load(*args: object) -> None:
        raise AssertionError("archive refusal must precede data loading")
    monkeypatch.setattr(run_origin_diagnostic, "load_records", unexpected_load)
    with pytest.raises(ValueError, match="historical origin evidence exists"):
        run_origin_diagnostic.main()
