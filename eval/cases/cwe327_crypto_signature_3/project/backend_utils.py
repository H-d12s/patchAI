import hashlib


def message_tag(message, key):
    """Signature sent with each message so the receiver can check it was not changed."""
    return hashlib.md5((key + message).encode()).hexdigest()


def verify_message(message, key, signature):
    return message_tag(message, key) == signature
