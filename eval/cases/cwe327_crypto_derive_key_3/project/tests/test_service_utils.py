from service_utils import make_encryption_key


def test_same_input_same_key():
    assert make_encryption_key("pw", b"salt1234") == make_encryption_key("pw", b"salt1234")


def test_salt_changes_the_key():
    assert make_encryption_key("pw", b"salt1234") != make_encryption_key("pw", b"salt5678")


def test_key_is_bytes():
    key = make_encryption_key("pw", b"salt1234")
    assert isinstance(key, bytes) and len(key) >= 16
