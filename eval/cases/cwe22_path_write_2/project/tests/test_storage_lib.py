import os

import storage_lib


def test_writes_into_the_folder(tmp_path, monkeypatch):
    monkeypatch.setattr(storage_lib, "REPORTS_DIR", str(tmp_path))
    path = storage_lib.write_report("data.csv", "a,b")
    assert os.path.dirname(os.path.realpath(path)) == os.path.realpath(tmp_path)
    assert (tmp_path / "data.csv").read_text() == "a,b"
