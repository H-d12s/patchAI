from pathlib import Path

import service_lib


def test_secret_is_not_in_the_code():
    assert "c7995994229c24c5ad69c19c" not in Path(service_lib.__file__).read_text(encoding="utf-8")
