import sqlite3

from tasks_app import VendorRepository


def make_repo():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE vendors (id INTEGER PRIMARY KEY, grade TEXT)")
    conn.executemany("INSERT INTO vendors (grade) VALUES (?)", [("alpha",), ("beta",), ("alpha",)])
    return VendorRepository(conn)
def test_injection_returns_nothing():
    assert make_repo().by_grade("x' OR '1'='1") == []


def test_quotes_are_handled():
    repo = make_repo()
    repo.conn.execute("INSERT INTO vendors (grade) VALUES (?)", ("o'neil",))
    assert repo.by_grade("o'neil") == [(4, "o'neil")]
