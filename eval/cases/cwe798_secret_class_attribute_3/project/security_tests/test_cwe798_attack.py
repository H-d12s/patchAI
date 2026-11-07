from pathlib import Path

import storage_utils


def test_secret_is_not_in_the_code():
    assert "ccbef4185082752846488219" not in Path(storage_utils.__file__).read_text(encoding="utf-8")
