import hashlib


def make_encryption_key(password, salt):
    """Turn a password into an encryption key."""
    return hashlib.sha1(salt + password.encode()).digest()
