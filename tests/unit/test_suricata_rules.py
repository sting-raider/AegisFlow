from pathlib import Path

import pytest

from scripts.update_suricata_rules import update


def test_rule_update_requires_https_and_lowercase_checksum() -> None:
    destination = Path("configs/suricata/rules/community.rules")
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        update("https://rules.invalid/rules", "not-a-digest", destination)
    with pytest.raises(ValueError, match="must use HTTPS"):
        update("http://rules.invalid/rules", "0" * 64, destination)


def test_rule_update_confines_destination() -> None:
    with pytest.raises(ValueError, match="only to configs/suricata/rules"):
        update("https://rules.invalid/rules", "0" * 64, Path("outside.rules"))
