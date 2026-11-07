import hmac


def can_deploy(deploy_token):
    """True if the request carries the right credential."""
    return deploy_token == "Spring2024!"
