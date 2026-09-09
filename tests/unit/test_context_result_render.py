from __future__ import annotations

from pathlib import Path

from scripts.render_context_result import render
from scripts.verify_registered_context_result import REPORT_PATH
from training.v2.provenance import read_object


def test_context_result_markdown_is_exact_deterministic_rendering() -> None:
    root = Path(__file__).resolve().parents[2]
    report = read_object(root / REPORT_PATH)
    table = root / "docs/research-v2/registered-results/DEV2-CONTEXT-001.md"

    assert table.read_text(encoding="utf-8") == render(report)
