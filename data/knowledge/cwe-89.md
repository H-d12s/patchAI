# CWE-89: SQL Injection

## What it is

SQL injection (CWE-89) happens when a program builds an SQL statement by gluing untrusted text into the query string, for example with an f-string, `%` formatting, `.format()` or `+`. The database cannot tell which part is the developer's SQL and which part is data, so a value containing quotes or SQL keywords changes what the query does. In Python it usually looks like `cursor.execute(f"... WHERE name = '{name}'")`. Untrusted values include anything from a request, form, URL, file, CLI argument or another service, including "numbers" that were never converted with `int()`. The fix for SQL injection is always the same idea: keep the SQL text fixed and send the values separately as query parameters.

## How attackers exploit it

To exploit SQL injection, an attacker sends input that closes the developer's string literal and adds their own SQL. Typical payloads:

- `' OR '1'='1` turns a login check or lookup into "match every row".
- `' UNION SELECT username, password_hash FROM users --` appends data from another table to the results.
- `1; DROP TABLE grades` stacks a second statement where the driver allows several.
- Time-based payloads such as `pg_sleep(5)` leak data one yes/no answer at a time, even when no output is shown.

The injected SQL runs with the application's database permissions, so the attacker can read private records, bypass authentication, change or delete data, and sometimes reach files or the operating system through database features.

## How to fix it in Python

To fix SQL injection, pass every value as a query parameter and never format it into the SQL string:

- `sqlite3`: use `?` placeholders: `conn.execute("SELECT * FROM notes WHERE owner = ?", (owner,))`. The second argument is a tuple, so one value needs a trailing comma.
- `psycopg` / `psycopg2`, `pymysql`, `mysql-connector`: use `%s` placeholders: `cur.execute("... WHERE email = %s", (email,))`. This `%s` is filled in by the driver; never apply Python's `%` operator to the query. Do not put quotes around placeholders.
- `LIKE` searches: put the wildcards in the value: `(f"%{term}%",)`.
- A variable list of ids: use `executemany`, or build one placeholder per item.
- Table names, column names and `ORDER BY` directions cannot be parameters. Check them against an allowlist, ideally a dict mapping each allowed option to a complete, fixed SQL string.
- SQLAlchemy: `text("... WHERE id = :id")` with a params dict, or the ORM query API.

## Unsafe example

This SQL injection example builds the query with an f-string, so the `username` argument can rewrite the SQL:

```python
import sqlite3

def find_user(conn: sqlite3.Connection, username: str):
    query = f"SELECT id, username, email FROM users WHERE username = '{username}'"
    return conn.execute(query).fetchone()

# find_user(conn, "x' OR '1'='1") returns a user without knowing any name
```

Calling it with `x' OR '1'='1` matches every row, and `' UNION SELECT ...` can pull data from other tables. The quotes around `{username}` give no protection, because the attacker supplies their own closing quote.

## Safe example

The SQL injection fix keeps the same function and only changes how the value reaches the database:

```python
import sqlite3

def find_user(conn: sqlite3.Connection, username: str):
    query = "SELECT id, username, email FROM users WHERE username = ?"
    return conn.execute(query, (username,)).fetchone()
```

When the user chooses a sort column, use an allowlist of complete queries, because column names cannot be placeholders:

```python
SORTED = {
    "name": "SELECT id, username FROM users ORDER BY username",
    "joined": "SELECT id, username FROM users ORDER BY created_at",
}

def list_users(conn, sort):
    if sort not in SORTED:
        raise ValueError(f"unsupported sort: {sort!r}")
    return conn.execute(SORTED[sort]).fetchall()
```

With psycopg the first query uses `%s` instead of `?`; everything else is the same.

## Common wrong fixes

These changes look like SQL injection fixes but leave the bug in place or break the code:

- Escaping quotes by hand, such as `name.replace("'", "''")`. It misses numeric contexts, backslash escapes in MySQL and other edge cases.
- Blacklisting characters or words like `;`, `--` or `UNION`. Attackers use other syntax and encodings.
- Keeping the f-string and adding more quotes around the value.
- Using Python `%` formatting with psycopg (`"... = '%s'" % email`) instead of passing a parameter tuple as the second argument.
- Putting a table or column name in a placeholder; the driver rejects it or treats it as a string literal.
- Adding `# nosec` or `# nosemgrep` to hide the scanner warning.
- Wrapping `execute` in try/except, which hides errors but does not stop injection.
- Deleting the query or the feature.

## Checklist for a correct fix

Before accepting an SQL injection fix, confirm:

- Every untrusted value reaches the database through placeholders (`?` for sqlite3, `%s` for psycopg and MySQL drivers) passed as the second argument to `execute`.
- No f-string, `.format()`, `%` operator or `+` puts user data into the SQL text.
- A single parameter is passed as a tuple with a trailing comma: `(value,)`.
- Any dynamic table, column or sort keyword comes from a fixed allowlist.
- The function keeps its name, parameters, return value and normal behaviour, so callers and tests still work and normal input returns the same rows.
- No new third-party imports, no `# nosec`, and no try/except used to hide the problem.
