from backend_utils import message_tag, verify_message


def test_signature_verifies():
    assert verify_message("hello", "k1", message_tag("hello", "k1"))


def test_signature_depends_on_the_key():
    assert message_tag("hello", "k1") != message_tag("hello", "k2")


def test_signature_is_stable():
    assert message_tag("x", "k") == message_tag("x", "k")
