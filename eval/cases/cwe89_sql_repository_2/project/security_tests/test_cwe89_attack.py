import sqlite3

from backend_lib import DonorRepository


def make_repo():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE donors (id INTEGER PRIMARY KEY, label TEXT)")
    conn.executemany("INSERT INTO donors (label) VALUES (?)", [("alpha",), ("beta",), ("alpha",)])
    return DonorRepository(conn)
def test_injection_returns_nothing():
    assert make_repo().by_label("x' OR '1'='1") == []


def test_quotes_are_handled():
    repo = make_repo()
    repo.conn.execute("INSERT INTO donors (label) VALUES (?)", ("o'neil",))
    assert repo.by_label("o'neil") == [(4, "o'neil")]
