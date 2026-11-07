from pathlib import Path

import tasks_utils


def test_credential_is_not_in_the_code():
    assert "admin-admin" not in Path(tasks_utils.__file__).read_text(encoding="utf-8")


def test_old_credential_no_longer_works():
    assert tasks_utils.is_admin("admin-admin") is False
