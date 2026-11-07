import sqlite3

from backend_lib import DonorRepository


def make_repo():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE donors (id INTEGER PRIMARY KEY, label TEXT)")
    conn.executemany("INSERT INTO donors (label) VALUES (?)", [("alpha",), ("beta",), ("alpha",)])
    return DonorRepository(conn)
def test_finds_matching_rows():
    assert make_repo().by_label("alpha") == [(1, "alpha"), (3, "alpha")]


def test_no_match():
    assert make_repo().by_label("gamma") == []
