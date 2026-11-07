import hashlib


def make_encryption_key(password, salt):
    """Turn a password into an encryption key."""
    return hashlib.md5(salt + password.encode()).digest()
