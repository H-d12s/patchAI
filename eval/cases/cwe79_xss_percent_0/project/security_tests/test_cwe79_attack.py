from backend_utils import app


def test_script_is_escaped():
    page = app.test_client().get("/filter?tag=<script>alert(1)</script>").get_data(as_text=True)
    assert "<script>" not in page


def test_tag_injection_is_escaped():
    page = app.test_client().get('/filter?tag="><img src=x onerror=alert(1)>').get_data(as_text=True)
    assert "<img" not in page
