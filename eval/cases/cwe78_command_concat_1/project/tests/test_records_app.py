
import subprocess


class Recorder:
    def __init__(self, exit_code=0):
        self.exit_code = exit_code
        self.shell = []
        self.processes = []

    def system(self, command):
        self.shell.append(command)
        return self.exit_code

    def process(self, args, *a, **kw):
        self.processes.append((args, kw))
        return subprocess.CompletedProcess(args, self.exit_code, b"", b"") if kw.pop("_run", True) else self.exit_code


def patch_all(monkeypatch, exit_code=0):
    rec = Recorder(exit_code)
    monkeypatch.setattr("os.system", rec.system)
    def run(args, *a, **kw):
        rec.processes.append((args, kw))
        return subprocess.CompletedProcess(args, exit_code, b"", b"")
    def call(args, *a, **kw):
        rec.processes.append((args, kw))
        return exit_code
    monkeypatch.setattr("subprocess.run", run)
    for name in ("call", "check_call"):
        monkeypatch.setattr(f"subprocess.{name}", call)
    monkeypatch.setattr("subprocess.check_output", lambda args, *a, **kw: rec.processes.append((args, kw)) or b"")
    return rec


from records_app import rename_file


def test_success(monkeypatch):
    rec = patch_all(monkeypatch, 0)
    assert rename_file("one.txt", "two.txt") is True
    assert "one.txt" in str(rec.processes + rec.shell) and "two.txt" in str(rec.processes + rec.shell)


def test_failure(monkeypatch):
    patch_all(monkeypatch, 1)
    assert rename_file("one.txt", "two.txt") is False
