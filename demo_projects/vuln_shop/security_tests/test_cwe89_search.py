"""SQL injection: a crafted search term must not change the query."""

from shop import db


def make_conn():
    conn = db.connect()
    db.init_db(conn)
    for name in ["Green Tea", "Coffee Beans", "Dark Chocolate"]:
        db.add_product(conn, name, 1.0)
    return conn


def test_or_true_injection_returns_nothing():
    conn = make_conn()
    assert db.search_products(conn, "' OR '1'='1") == []


def test_union_injection_returns_nothing():
    conn = make_conn()
    assert db.search_products(conn, "x' UNION SELECT 1, sqlite_version(), 0, 0 --") == []


def test_names_with_quotes_work():
    # The same bug that allows injection also breaks searches containing an apostrophe.
    conn = make_conn()
    db.add_product(conn, "Grandma's Jam", 4.0)
    assert [p["name"] for p in db.search_products(conn, "Grandma's")] == ["Grandma's Jam"]
