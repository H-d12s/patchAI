"""The shop's web pages."""

from flask import Blueprint, abort, current_app, request

from shop import accounts, db, invoices, suppliers

bp = Blueprint("shop", __name__)


def get_conn():
    return current_app.config["DB"]


@bp.route("/")
def index():
    return "<h1>Corner Shop</h1><p>Search our products at /search?q=tea</p>"


@bp.route("/search")
def search():
    q = request.args.get("q", "")
    results = db.search_products(get_conn(), q)
    items = "".join(f"<li>{p['name']} - ${p['price']:.2f}</li>" for p in results)
    return f"<h1>Results for {q}</h1><ul>{items}</ul>"


@bp.route("/product/<int:product_id>")
def product(product_id: int):
    item = db.get_product(get_conn(), product_id)
    if item is None:
        abort(404)
    return item


@bp.route("/invoice/<name>")
def invoice(name: str):
    try:
        text = invoices.read_invoice(name)
    except (OSError, ValueError):
        abort(404)
    return text, 200, {"Content-Type": "text/plain; charset=utf-8"}


@bp.route("/admin/login", methods=["POST"])
def admin_login():
    if accounts.check_admin_password(request.form.get("password", "")):
        return {"ok": True}
    return {"ok": False}, 403


@bp.route("/suppliers/check")
def supplier_check():
    host = request.args.get("host", "")
    return {"host": host, "online": suppliers.check_supplier(host)}
