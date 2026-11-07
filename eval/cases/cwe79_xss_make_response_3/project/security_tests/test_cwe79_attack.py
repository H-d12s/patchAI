from helpers_utils import app


def test_script_is_escaped():
    page = app.test_client().get("/user?handle=<script>alert(1)</script>").get_data(as_text=True)
    assert "<script>" not in page
