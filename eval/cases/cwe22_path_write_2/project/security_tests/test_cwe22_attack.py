import storage_lib


def test_cannot_write_outside_the_folder(tmp_path, monkeypatch):
    folder = tmp_path / "output"
    folder.mkdir()
    monkeypatch.setattr(storage_lib, "REPORTS_DIR", str(folder))
    try:
        storage_lib.write_report("../escaped.txt", "pwned")
    except Exception:
        pass
    assert not (tmp_path / "escaped.txt").exists()
