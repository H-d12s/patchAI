"""Invoices are stored as text files in the invoices folder."""

import os

from shop import config


def read_invoice(filename: str) -> str:
    """Return the text of an invoice from the invoices folder."""
    path = os.path.join(config.INVOICE_DIR, filename)
    with open(path, encoding="utf-8") as f:
        return f.read()


def list_invoices() -> list[str]:
    """Names of all stored invoices."""
    return sorted(name for name in os.listdir(config.INVOICE_DIR) if name.endswith(".txt"))
