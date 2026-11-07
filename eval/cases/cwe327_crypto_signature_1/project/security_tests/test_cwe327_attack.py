import hashlib

from helpers_utils import sign_request


def test_signature_is_not_a_plain_weak_hash():
    sig = sign_request("amount=10", "secret-key")
    for algo in ("md5", "sha1"):
        assert sig != hashlib.new(algo, b"secret-keyamount=10").hexdigest()
    assert len(sig) >= 64
