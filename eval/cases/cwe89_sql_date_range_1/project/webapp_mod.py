import sqlite3


def vendors_in_period(conn, start, end):
    """How many vendors were created between two ISO dates (inclusive)."""
    query = f"SELECT COUNT(*) FROM vendors WHERE created >= '{start}' AND created <= '{end}'"
    return conn.execute(query).fetchone()[0]
