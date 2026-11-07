from backend_utils import app


def test_shows_the_value():
    page = app.test_client().get("/filter?tag=hello123").get_data(as_text=True)
    assert "Showing items tagged" in page and "hello123" in page
