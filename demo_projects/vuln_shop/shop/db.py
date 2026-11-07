"""Database helpers for the shop (SQLite)."""

import sqlite3


def connect(path: str = ":memory:") -> sqlite3.Connection:
    """Open the database. Rows can be read like dictionaries."""
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Create the tables if they don't exist yet."""
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            price REAL NOT NULL,
            stock INTEGER NOT NULL DEFAULT 0
        );
        """
    )


def rows_to_dicts(cursor: sqlite3.Cursor) -> list[dict]:
    """Turn query results into plain dictionaries."""
    return [dict(row) for row in cursor.fetchall()]


def run_query(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> list[dict]:
    """Run a SELECT with ? placeholders and return the rows as dictionaries."""
    return rows_to_dicts(conn.execute(sql, params))


def add_product(conn: sqlite3.Connection, name: str, price: float, stock: int = 0) -> int:
    """Add a product and return its id."""
    cursor = conn.execute(
        "INSERT INTO products (name, price, stock) VALUES (?, ?, ?)", (name, price, stock)
    )
    conn.commit()
    return cursor.lastrowid


def get_product(conn: sqlite3.Connection, product_id: int) -> dict | None:
    """One product by id, or None."""
    rows = run_query(conn, "SELECT id, name, price, stock FROM products WHERE id = ?", (product_id,))
    return rows[0] if rows else None


def search_products(conn: sqlite3.Connection, term: str) -> list[dict]:
    """Products whose name contains `term`, sorted by name."""
    sql = f"SELECT id, name, price, stock FROM products WHERE name LIKE '%{term}%' ORDER BY name"
    return rows_to_dicts(conn.execute(sql))
