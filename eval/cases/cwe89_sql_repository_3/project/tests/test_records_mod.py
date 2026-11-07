import sqlite3

from records_mod import AssetRepository


def make_repo():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE assets (id INTEGER PRIMARY KEY, region TEXT)")
    conn.executemany("INSERT INTO assets (region) VALUES (?)", [("alpha",), ("beta",), ("alpha",)])
    return AssetRepository(conn)
def test_finds_matching_rows():
    assert make_repo().by_region("alpha") == [(1, "alpha"), (3, "alpha")]


def test_no_match():
    assert make_repo().by_region("gamma") == []
