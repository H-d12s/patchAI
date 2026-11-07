import service_lib


def test_cannot_write_outside_the_folder(tmp_path, monkeypatch):
    folder = tmp_path / "output"
    folder.mkdir()
    monkeypatch.setattr(service_lib, "EXPORT_DIR", str(folder))
    try:
        service_lib.save_export("../escaped.txt", "pwned")
    except Exception:
        pass
    assert not (tmp_path / "escaped.txt").exists()
