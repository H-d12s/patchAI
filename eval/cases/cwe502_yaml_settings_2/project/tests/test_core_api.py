from core_api import load_preferences


def test_overrides_defaults():
    assert load_preferences("theme: dark") == {"theme": "dark", "page_size": 20}


def test_empty_file_gives_defaults():
    assert load_preferences("") == {"theme": "light", "page_size": 20}
