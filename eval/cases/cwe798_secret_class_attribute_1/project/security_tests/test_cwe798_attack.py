from pathlib import Path

import storage_lib


def test_secret_is_not_in_the_code():
    assert "fb6461bd482319b52ce5f7d9" not in Path(storage_lib.__file__).read_text(encoding="utf-8")
