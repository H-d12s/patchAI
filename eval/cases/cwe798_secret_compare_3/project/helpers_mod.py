import hmac


def check_api_key(api_token):
    """True if the request carries the right credential."""
    return api_token == "Spring2024!"
