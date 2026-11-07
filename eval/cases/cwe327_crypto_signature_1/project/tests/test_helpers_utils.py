from helpers_utils import sign_request, verify_request


def test_signature_verifies():
    assert verify_request("hello", "k1", sign_request("hello", "k1"))


def test_signature_depends_on_the_key():
    assert sign_request("hello", "k1") != sign_request("hello", "k2")


def test_signature_is_stable():
    assert sign_request("x", "k") == sign_request("x", "k")
