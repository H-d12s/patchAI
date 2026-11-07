from helpers_mod import check_api_key


def test_wrong_credential_is_rejected():
    assert check_api_key("wrong") is False
