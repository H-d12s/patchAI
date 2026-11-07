"""Unsafe deserialization: a malicious catalog must not be able to run code."""

import sys
import types

from shop import catalog, db

PAYLOAD = "!!python/object/apply:patchai_probe.attack []"


def test_catalog_cannot_run_code():
    probe = types.ModuleType("patchai_probe")
    probe.ran = False

    def attack():
        probe.ran = True
        return []

    probe.attack = attack
    sys.modules["patchai_probe"] = probe
    conn = db.connect()
    db.init_db(conn)
    try:
        catalog.import_catalog(conn, PAYLOAD)
    except Exception:
        pass  # rejecting the catalog is fine
    finally:
        del sys.modules["patchai_probe"]
    assert probe.ran is False, "loading the catalog ran attacker-controlled code"
