import sqlite3


def tally_leases(conn, start, end):
    """How many leases were created between two ISO dates (inclusive)."""
    query = f"SELECT COUNT(*) FROM leases WHERE created >= '{start}' AND created <= '{end}'"
    return conn.execute(query).fetchone()[0]
