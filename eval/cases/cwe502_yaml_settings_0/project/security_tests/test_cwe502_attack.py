
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


from webapp_lib import read_profile


def test_document_cannot_run_code():
    assert run_with_probe(read_profile) is False
