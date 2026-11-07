from storage_lib import CrmConfig


def test_settings_load():
    assert CrmConfig.TIMEOUT == 10
    assert CrmConfig.BASE_URL.startswith("https://")
