import handlers_app


def test_cannot_write_outside_the_folder(tmp_path, monkeypatch):
    folder = tmp_path / "output"
    folder.mkdir()
    monkeypatch.setattr(handlers_app, "REPORTS_DIR", str(folder))
    try:
        handlers_app.write_report("../escaped.txt", "pwned")
    except Exception:
        pass
    assert not (tmp_path / "escaped.txt").exists()
