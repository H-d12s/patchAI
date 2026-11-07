import sqlite3


def donors_in_period(conn, start, end):
    """How many donors were created between two ISO dates (inclusive)."""
    query = f"SELECT COUNT(*) FROM donors WHERE created >= '{start}' AND created <= '{end}'"
    return conn.execute(query).fetchone()[0]
