from storage_mod import app


def test_shows_the_value():
    page = app.test_client().get("/lookup?term=hello123").get_data(as_text=True)
    assert "You searched for" in page and "hello123" in page
