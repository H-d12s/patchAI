"""Command injection: the host name must never be run through a shell."""

import subprocess

from shop import suppliers


class Recorder:
    def __init__(self):
        self.shell_commands = []
        self.process_calls = []

    def system(self, command):
        self.shell_commands.append(command)
        return 0

    def process(self, args, *a, **kw):
        self.process_calls.append((args, kw))
        return subprocess.CompletedProcess(args, 0, b"", b"")


def test_injected_command_is_not_run_by_a_shell(monkeypatch):
    rec = Recorder()
    monkeypatch.setattr("os.system", rec.system)
    for name in ("run", "call", "check_call", "check_output"):
        monkeypatch.setattr(f"subprocess.{name}", rec.process)

    suppliers.check_supplier("example.com; echo hacked")

    assert rec.shell_commands == [], "os.system runs the input through a shell"
    for args, kw in rec.process_calls:
        assert kw.get("shell") is not True, "shell=True runs the input through a shell"
        assert isinstance(args, (list, tuple)), "the command must be a list of arguments"
        assert "example.com; echo hacked" in args, "the host must be passed as one argument"
