import os

import records_mod


def test_writes_into_the_folder(tmp_path, monkeypatch):
    monkeypatch.setattr(records_mod, "EXPORT_DIR", str(tmp_path))
    path = records_mod.save_export("data.csv", "a,b")
    assert os.path.dirname(os.path.realpath(path)) == os.path.realpath(tmp_path)
    assert (tmp_path / "data.csv").read_text() == "a,b"
