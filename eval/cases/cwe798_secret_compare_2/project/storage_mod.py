import hmac


def is_operator(password):
    """True if the request carries the right credential."""
    return password == "letmein-2024"
