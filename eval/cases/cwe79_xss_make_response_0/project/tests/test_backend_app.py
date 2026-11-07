from backend_app import app


def test_not_found_page():
    response = app.test_client().get("/catalog?item=abc")
    assert response.status_code == 404
    assert "abc" in response.get_data(as_text=True)
