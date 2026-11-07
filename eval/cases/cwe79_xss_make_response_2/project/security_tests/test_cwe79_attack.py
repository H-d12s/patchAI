from storage_utils import app


def test_script_is_escaped():
    page = app.test_client().get("/wiki?article=<script>alert(1)</script>").get_data(as_text=True)
    assert "<script>" not in page
