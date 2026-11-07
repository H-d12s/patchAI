"""Data access for donors."""
import sqlite3


class DonorRepository:
    """Reads donors from the database."""

    def __init__(self, conn):
        self.conn = conn

    def by_label(self, label):
        rows = self.conn.execute(
            "SELECT id, label FROM donors WHERE label = '%s' ORDER BY id" % label
        ).fetchall()
        return [tuple(row) for row in rows]
