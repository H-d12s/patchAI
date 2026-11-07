"""Admin login and password-reset tokens."""

import hashlib
import hmac
import time

from shop import config


def check_admin_password(password: str) -> bool:
    """True if `password` is the admin password."""
    expected = config.ADMIN_PASSWORD
    if not expected:
        return False
    return hmac.compare_digest(password.encode(), expected.encode())


def make_reset_token(email: str) -> str:
    """A token emailed to a user so they can reset their password."""
    raw = f"{email}:{int(time.time())}"
    return hashlib.md5(raw.encode()).hexdigest()
