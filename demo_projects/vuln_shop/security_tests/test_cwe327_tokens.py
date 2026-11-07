"""Weak cryptography: reset tokens must be unpredictable, even for the same email at the same second."""

import hashlib

from shop import accounts


def test_tokens_are_not_predictable(monkeypatch):
    monkeypatch.setattr("time.time", lambda: 1_700_000_000)
    first = accounts.make_reset_token("sam@example.com")
    second = accounts.make_reset_token("sam@example.com")
    assert first != second, "an attacker who knows the email and time could compute the token"


def test_token_is_not_a_hash_of_email_and_time(monkeypatch):
    monkeypatch.setattr("time.time", lambda: 1_700_000_000)
    token = accounts.make_reset_token("sam@example.com")
    raw = b"sam@example.com:1700000000"
    for algorithm in ("md5", "sha1", "sha256"):
        assert token != hashlib.new(algorithm, raw).hexdigest()
