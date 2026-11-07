import hashlib

from core_app import key_from_password


def test_key_is_not_a_single_fast_hash():
    key = key_from_password("pw", b"salt1234")
    for algo in ("md5", "sha1", "sha256", "sha512"):
        assert key != hashlib.new(algo, b"salt1234pw").digest(), f"one round of {algo} is cracked quickly"
