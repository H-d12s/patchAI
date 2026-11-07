"""Known-good (and known-bad) fixes for the demo shop, used to test the pipeline without a model."""

from patchai.models import FixProposal

GOOD_FIXES: dict[str, FixProposal] = {
    "CWE-89": FixProposal(
        status="fixed",
        fixed_code='''def search_products(conn: sqlite3.Connection, term: str) -> list[dict]:
    """Products whose name contains `term`, sorted by name."""
    sql = "SELECT id, name, price, stock FROM products WHERE name LIKE ? ORDER BY name"
    return run_query(conn, sql, (f"%{term}%",))''',
        explanation="The search term is now passed as a query parameter instead of being pasted into the SQL.",
        confidence=0.95,
    ),
    "CWE-79": FixProposal(
        status="fixed",
        fixed_code='''@bp.route("/search")
def search():
    q = request.args.get("q", "")
    results = db.search_products(get_conn(), q)
    items = "".join(f"<li>{escape(p['name'])} - ${p['price']:.2f}</li>" for p in results)
    return f"<h1>Results for {escape(q)}</h1><ul>{items}</ul>"''',
        imports_to_add=["from markupsafe import escape"],
        explanation="User input is HTML-escaped before it is put into the page.",
        confidence=0.9,
    ),
    "CWE-22": FixProposal(
        status="fixed",
        fixed_code='''def read_invoice(filename: str) -> str:
    """Return the text of an invoice from the invoices folder."""
    base = os.path.realpath(config.INVOICE_DIR)
    path = os.path.realpath(os.path.join(base, filename))
    if os.path.commonpath([base, path]) != base:
        raise ValueError("Invalid invoice name")
    with open(path, encoding="utf-8") as f:
        return f.read()''',
        explanation="The resolved path must stay inside the invoices folder.",
        confidence=0.9,
    ),
    "CWE-78": FixProposal(
        status="fixed",
        fixed_code='''def check_supplier(host: str) -> bool:
    """Ping a supplier's server once. True if it answered."""
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True)
    return result.returncode == 0''',
        imports_to_add=["import subprocess"],
        explanation="The host is passed as a single argument without a shell.",
        confidence=0.9,
    ),
    "CWE-798": FixProposal(
        status="fixed",
        fixed_code='ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")',
        explanation="The admin password is read from an environment variable.",
        confidence=0.9,
    ),
    "CWE-327": FixProposal(
        status="fixed",
        fixed_code='''def make_reset_token(email: str) -> str:
    """A token emailed to a user so they can reset their password."""
    return secrets.token_urlsafe(32)''',
        imports_to_add=["import secrets"],
        explanation="Tokens are now random instead of a hash of guessable values.",
        confidence=0.9,
    ),
    "CWE-502": FixProposal(
        status="fixed",
        fixed_code='''def import_catalog(conn, yaml_text: str) -> int:
    """Add every product in a YAML catalog. Returns how many were added."""
    items = yaml.safe_load(yaml_text)
    for item in items:
        db.add_product(conn, item["name"], float(item["price"]), int(item.get("stock", 0)))
    return len(items)''',
        explanation="safe_load only builds plain data, never Python objects.",
        confidence=0.95,
    ),
}

# A "fake fix": the scanner stops complaining, but tokens are still predictable.
FAKE_TOKEN_FIX = FixProposal(
    status="fixed",
    fixed_code='''def make_reset_token(email: str) -> str:
    """A token emailed to a user so they can reset their password."""
    raw = f"{email}:{int(time.time())}"
    return hashlib.sha256(raw.encode()).hexdigest()''',
    explanation="Uses SHA-256 instead of MD5.",
    confidence=0.8,
)

# A hallucinated package that does not exist.
HALLUCINATED_FIX = FixProposal(
    status="fixed",
    fixed_code='''def search_products(conn: sqlite3.Connection, term: str) -> list[dict]:
    """Products whose name contains `term`, sorted by name."""
    return sqlsafe.query(conn, "products", name_like=term)''',
    imports_to_add=["import sqlsafe"],
    explanation="Uses the sqlsafe library.",
    confidence=0.7,
)

# Escaping quotes by hand: still string-built SQL, so the re-scan rejects it.
HAND_ESCAPED_FIX = FixProposal(
    status="fixed",
    fixed_code='''def search_products(conn: sqlite3.Connection, term: str) -> list[dict]:
    """Products whose name contains `term`, sorted by name."""
    term = term.replace("'", "''")
    sql = f"SELECT id, name, price, stock FROM products WHERE name LIKE '%{term}%' ORDER BY name"
    return rows_to_dicts(conn.execute(sql))''',
    explanation="Escapes quotes.",
    confidence=0.6,
)
