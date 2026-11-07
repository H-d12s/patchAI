"""Corner Shop: a tiny online shop used to demonstrate PatchAI.

WARNING: this app is intentionally vulnerable. Never deploy it.
"""

from flask import Flask

from shop import db


def create_app(db_path: str = ":memory:") -> Flask:
    """Create the shop app with a few products in the database."""
    app = Flask(__name__)
    conn = db.connect(db_path)
    db.init_db(conn)
    for name, price, stock in [("Green Tea", 3.50, 20), ("Coffee Beans", 9.99, 5), ("Dark Chocolate", 2.25, 50)]:
        db.add_product(conn, name, price, stock)
    app.config["DB"] = conn

    from shop.views import bp

    app.register_blueprint(bp)
    return app
