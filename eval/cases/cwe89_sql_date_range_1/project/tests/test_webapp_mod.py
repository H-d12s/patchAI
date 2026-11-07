import sqlite3

from webapp_mod import vendors_in_period


def make_db():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE vendors (id INTEGER PRIMARY KEY, created TEXT)")
    conn.executemany("INSERT INTO vendors (created) VALUES (?)", [("2024-01-05",), ("2024-02-10",), ("2024-03-15",)])
    return conn
def test_counts_rows_in_range():
    assert vendors_in_period(make_db(), "2024-01-01", "2024-02-28") == 2


def test_empty_range():
    assert vendors_in_period(make_db(), "2025-01-01", "2025-12-31") == 0
