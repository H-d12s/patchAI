import sqlite3

from records_mod import AssetRepository


def make_repo():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE assets (id INTEGER PRIMARY KEY, region TEXT)")
    conn.executemany("INSERT INTO assets (region) VALUES (?)", [("alpha",), ("beta",), ("alpha",)])
    return AssetRepository(conn)
def test_injection_returns_nothing():
    assert make_repo().by_region("x' OR '1'='1") == []


def test_quotes_are_handled():
    repo = make_repo()
    repo.conn.execute("INSERT INTO assets (region) VALUES (?)", ("o'neil",))
    assert repo.by_region("o'neil") == [(4, "o'neil")]
