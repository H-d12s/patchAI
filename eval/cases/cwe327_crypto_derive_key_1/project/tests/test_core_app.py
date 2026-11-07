from core_app import key_from_password


def test_same_input_same_key():
    assert key_from_password("pw", b"salt1234") == key_from_password("pw", b"salt1234")


def test_salt_changes_the_key():
    assert key_from_password("pw", b"salt1234") != key_from_password("pw", b"salt5678")


def test_key_is_bytes():
    key = key_from_password("pw", b"salt1234")
    assert isinstance(key, bytes) and len(key) >= 16
