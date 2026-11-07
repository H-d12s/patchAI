"""Bulk-import products from a YAML catalog uploaded by a supplier."""

import yaml

from shop import db


def import_catalog(conn, yaml_text: str) -> int:
    """Add every product in a YAML catalog. Returns how many were added."""
    items = yaml.load(yaml_text, Loader=yaml.Loader)
    for item in items:
        db.add_product(conn, item["name"], float(item["price"]), int(item.get("stock", 0)))
    return len(items)
