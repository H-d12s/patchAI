
import sys
import types


def run_with_probe(load):
    """Load a malicious document that calls patchai_probe.attack(); report whether it ran."""
    probe = types.ModuleType("patchai_probe")
    probe.ran = False

    def attack():
        probe.ran = True
        return {}

    probe.attack = attack
    sys.modules["patchai_probe"] = probe
    try:
        load("!!python/object/apply:patchai_probe.attack []")
    except Exception:
        pass
    finally:
        del sys.modules["patchai_probe"]
    return probe.ran


import os
import tempfile

from handlers_utils import WorkflowSpec


def test_file_cannot_run_code():
    def load(text):
        fd, path = tempfile.mkstemp(suffix=".yaml")
        with os.fdopen(fd, "w") as f:
            f.write(text)
        try:
            return WorkflowSpec(path).load()
        finally:
            os.remove(path)
    assert run_with_probe(load) is False
