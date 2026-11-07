from pathlib import Path

import storage_mod


def test_credential_is_not_in_the_code():
    assert "letmein-2024" not in Path(storage_mod.__file__).read_text(encoding="utf-8")


def test_old_credential_no_longer_works():
    assert storage_mod.is_operator("letmein-2024") is False
