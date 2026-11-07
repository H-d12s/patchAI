import sqlite3

from core_utils import count_vendors_between


def make_db():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE vendors (id INTEGER PRIMARY KEY, created TEXT)")
    conn.executemany("INSERT INTO vendors (created) VALUES (?)", [("2024-01-05",), ("2024-02-10",), ("2024-03-15",)])
    return conn
def test_injection_does_not_change_the_count():
    assert count_vendors_between(make_db(), "2099-01-01' OR '1'='1", "2024-12-31") == 0
