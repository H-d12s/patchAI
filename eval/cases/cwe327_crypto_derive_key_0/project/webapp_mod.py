import hashlib


def key_from_password(password, salt):
    """Turn a password into an encryption key."""
    return hashlib.md5(salt + password.encode()).digest()
