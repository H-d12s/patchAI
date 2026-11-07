"""Path traversal: invoice names must not be able to reach files outside the invoices folder."""

import os

import shop
from shop import invoices


def _cannot_read(name: str, marker: str) -> bool:
    try:
        text = invoices.read_invoice(name)
    except Exception:
        return True
    return marker not in text


def test_dot_dot_slash_cannot_escape():
    assert _cannot_read("../config.py", "INVOICE_DIR")


def test_absolute_path_cannot_escape():
    assert _cannot_read(os.path.abspath(shop.__file__), "create_app")


def test_normal_invoice_still_works():
    assert "INV-1001" in invoices.read_invoice("INV-1001.txt")
