import pytest

from shop import create_app, db


@pytest.fixture
def app():
    return create_app()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def conn():
    connection = db.connect()
    db.init_db(connection)
    for name, price in [("Green Tea", 3.5), ("Coffee Beans", 9.99), ("Dark Chocolate", 2.25)]:
        db.add_product(connection, name, price, 10)
    return connection
