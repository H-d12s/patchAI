from storage_mod import is_operator


def test_wrong_credential_is_rejected():
    assert is_operator("wrong") is False
