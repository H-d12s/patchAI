"""Hard-coded secret: the admin password must not be written in the source code."""

from pathlib import Path

import shop


def test_admin_password_is_not_in_the_code():
    source = (Path(shop.__file__).parent / "config.py").read_text(encoding="utf-8")
    assert "shopadmin2024" not in source


def test_password_can_come_from_the_environment(monkeypatch):
    import importlib

    from shop import config

    for name in ("ADMIN_PASSWORD", "SHOP_ADMIN_PASSWORD", "CORNER_SHOP_ADMIN_PASSWORD"):
        monkeypatch.setenv(name, "from-env-123")
    importlib.reload(config)
    assert config.ADMIN_PASSWORD == "from-env-123"
