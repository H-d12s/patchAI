import sqlite3

from storage_api import tally_leases


def make_db():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE leases (id INTEGER PRIMARY KEY, created TEXT)")
    conn.executemany("INSERT INTO leases (created) VALUES (?)", [("2024-01-05",), ("2024-02-10",), ("2024-03-15",)])
    return conn
def test_injection_does_not_change_the_count():
    assert tally_leases(make_db(), "2099-01-01' OR '1'='1", "2024-12-31") == 0
