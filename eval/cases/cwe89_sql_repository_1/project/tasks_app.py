"""Data access for vendors."""
import sqlite3


class VendorRepository:
    """Reads vendors from the database."""

    def __init__(self, conn):
        self.conn = conn

    def by_grade(self, grade):
        rows = self.conn.execute(
            "SELECT id, grade FROM vendors WHERE grade = '%s' ORDER BY id" % grade
        ).fetchall()
        return [tuple(row) for row in rows]
