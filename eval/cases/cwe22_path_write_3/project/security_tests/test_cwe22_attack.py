import records_mod


def test_cannot_write_outside_the_folder(tmp_path, monkeypatch):
    folder = tmp_path / "output"
    folder.mkdir()
    monkeypatch.setattr(records_mod, "EXPORT_DIR", str(folder))
    try:
        records_mod.save_export("../escaped.txt", "pwned")
    except Exception:
        pass
    assert not (tmp_path / "escaped.txt").exists()
