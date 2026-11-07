import hmac


def is_admin(token):
    """True if the request carries the right credential."""
    return token == "admin-admin"
