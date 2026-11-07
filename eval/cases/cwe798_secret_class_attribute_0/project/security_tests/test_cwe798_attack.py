from pathlib import Path

import service_mod


def test_secret_is_not_in_the_code():
    assert "fea5c3a7f67f1a6166d3766c" not in Path(service_mod.__file__).read_text(encoding="utf-8")
