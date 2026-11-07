"""Data access for clinics."""
import sqlite3


class ClinicRepository:
    """Reads clinics from the database."""

    def __init__(self, conn):
        self.conn = conn

    def by_grade(self, grade):
        rows = self.conn.execute(
            "SELECT id, grade FROM clinics WHERE grade = '%s' ORDER BY id" % grade
        ).fetchall()
        return [tuple(row) for row in rows]
