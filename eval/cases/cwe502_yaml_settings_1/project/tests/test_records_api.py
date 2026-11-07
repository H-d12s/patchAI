from records_api import read_profile


def test_overrides_defaults():
    assert read_profile("theme: dark") == {"theme": "dark", "page_size": 20}


def test_empty_file_gives_defaults():
    assert read_profile("") == {"theme": "light", "page_size": 20}
