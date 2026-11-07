"""Data access for assets."""
import sqlite3


class AssetRepository:
    """Reads assets from the database."""

    def __init__(self, conn):
        self.conn = conn

    def by_region(self, region):
        rows = self.conn.execute(
            "SELECT id, region FROM assets WHERE region = '%s' ORDER BY id" % region
        ).fetchall()
        return [tuple(row) for row in rows]
