"""Checks whether our suppliers' servers are online."""

import os


def check_supplier(host: str) -> bool:
    """Ping a supplier's server once. True if it answered."""
    exit_code = os.system(f"ping -c 1 {host}")
    return exit_code == 0
