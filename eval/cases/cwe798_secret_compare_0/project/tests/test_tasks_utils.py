from tasks_utils import is_admin


def test_wrong_credential_is_rejected():
    assert is_admin("wrong") is False
