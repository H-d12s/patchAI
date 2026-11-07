"""Cross-site scripting: user input must be escaped before it is put into HTML."""

from shop import create_app


def test_script_tag_in_search_is_escaped():
    client = create_app().test_client()
    page = client.get("/search?q=<script>alert(1)</script>").get_data(as_text=True)
    assert "<script>" not in page


def test_html_attribute_injection_is_escaped():
    client = create_app().test_client()
    page = client.get('/search?q=<img src=x onerror="alert(1)">').get_data(as_text=True)
    assert "<img" not in page
