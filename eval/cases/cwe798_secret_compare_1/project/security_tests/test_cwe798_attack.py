from pathlib import Path

import helpers_mod


def test_credential_is_not_in_the_code():
    assert "Spring2024!" not in Path(helpers_mod.__file__).read_text(encoding="utf-8")


def test_old_credential_no_longer_works():
    assert helpers_mod.can_deploy("Spring2024!") is False
