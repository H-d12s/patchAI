import sqlite3

from tasks_app import VendorRepository


def make_repo():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE vendors (id INTEGER PRIMARY KEY, grade TEXT)")
    conn.executemany("INSERT INTO vendors (grade) VALUES (?)", [("alpha",), ("beta",), ("alpha",)])
    return VendorRepository(conn)
def test_finds_matching_rows():
    assert make_repo().by_grade("alpha") == [(1, "alpha"), (3, "alpha")]


def test_no_match():
    assert make_repo().by_grade("gamma") == []
