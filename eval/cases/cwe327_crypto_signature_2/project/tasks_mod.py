import hashlib


def sign_request(body, key):
    """Signature sent with each request so the receiver can check it was not changed."""
    return hashlib.sha1((key + body).encode()).hexdigest()


def verify_request(body, key, signature):
    return sign_request(body, key) == signature
