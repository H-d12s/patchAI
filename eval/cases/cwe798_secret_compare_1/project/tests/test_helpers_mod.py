from helpers_mod import can_deploy


def test_wrong_credential_is_rejected():
    assert can_deploy("wrong") is False
