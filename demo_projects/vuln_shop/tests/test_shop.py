"""Normal behaviour of the shop. These must pass before AND after a security fix."""

import subprocess

import yaml

from shop import accounts, catalog, db, invoices, suppliers


# ---- database ----

def test_search_finds_matching_products(conn):
    names = [p["name"] for p in db.search_products(conn, "Tea")]
    assert names == ["Green Tea"]


def test_search_is_case_insensitive_and_partial(conn):
    names = [p["name"] for p in db.search_products(conn, "co")]
    assert names == ["Coffee Beans", "Dark Chocolate"]


def test_search_with_no_match_returns_empty_list(conn):
    assert db.search_products(conn, "Pizza") == []


def test_get_product(conn):
    assert db.get_product(conn, 1)["name"] == "Green Tea"
    assert db.get_product(conn, 999) is None


# ---- web pages ----

def test_search_page_lists_results(client):
    page = client.get("/search?q=Tea").get_data(as_text=True)
    assert "Results for Tea" in page
    assert "Green Tea" in page


def test_product_page(client):
    assert client.get("/product/1").get_json()["name"] == "Green Tea"
    assert client.get("/product/999").status_code == 404


def test_invoice_page(client):
    response = client.get("/invoice/INV-1001.txt")
    assert response.status_code == 200
    assert "INV-1001" in response.get_data(as_text=True)


def test_missing_invoice_is_404(client):
    assert client.get("/invoice/INV-9999.txt").status_code == 404


def test_wrong_admin_password_is_rejected(client):
    assert client.post("/admin/login", data={"password": "guess"}).status_code == 403


# ---- invoices ----

def test_read_invoice():
    assert "Total" in invoices.read_invoice("INV-1001.txt")


def test_list_invoices():
    assert "INV-1001.txt" in invoices.list_invoices()


# ---- accounts ----

def test_wrong_password_is_rejected():
    assert accounts.check_admin_password("not-the-password") is False


def test_reset_token_looks_like_a_token():
    token = accounts.make_reset_token("sam@example.com")
    assert isinstance(token, str)
    assert len(token) >= 16


# ---- suppliers ----

class FakeShell:
    """Replaces os.system and subprocess so tests never run real commands."""

    def __init__(self, exit_code):
        self.exit_code = exit_code
        self.calls = []

    def system(self, command):
        self.calls.append(command)
        return self.exit_code

    def run(self, args, *a, **kw):
        self.calls.append(args)
        return subprocess.CompletedProcess(args, self.exit_code, b"", b"")

    def call(self, args, *a, **kw):
        self.calls.append(args)
        return self.exit_code


def _patch_shell(monkeypatch, exit_code):
    fake = FakeShell(exit_code)
    monkeypatch.setattr("os.system", fake.system)
    monkeypatch.setattr("subprocess.run", fake.run)
    monkeypatch.setattr("subprocess.call", fake.call)
    return fake


def test_supplier_online(monkeypatch):
    fake = _patch_shell(monkeypatch, 0)
    assert suppliers.check_supplier("supplier.example.com") is True
    assert "supplier.example.com" in str(fake.calls)


def test_supplier_offline(monkeypatch):
    _patch_shell(monkeypatch, 1)
    assert suppliers.check_supplier("down.example.com") is False


# ---- catalog ----

def test_import_catalog(conn):
    text = yaml.safe_dump([{"name": "Honey", "price": 5.5, "stock": 3}, {"name": "Oat Milk", "price": 2.0}])
    assert catalog.import_catalog(conn, text) == 2
    assert [p["name"] for p in db.search_products(conn, "Honey")] == ["Honey"]
