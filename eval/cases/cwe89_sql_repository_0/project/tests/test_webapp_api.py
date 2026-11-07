import sqlite3

from webapp_api import ClinicRepository


def make_repo():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE clinics (id INTEGER PRIMARY KEY, grade TEXT)")
    conn.executemany("INSERT INTO clinics (grade) VALUES (?)", [("alpha",), ("beta",), ("alpha",)])
    return ClinicRepository(conn)
def test_finds_matching_rows():
    assert make_repo().by_grade("alpha") == [(1, "alpha"), (3, "alpha")]


def test_no_match():
    assert make_repo().by_grade("gamma") == []
