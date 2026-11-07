from storage_utils import MailConfig


def test_settings_load():
    assert MailConfig.TIMEOUT == 10
    assert MailConfig.BASE_URL.startswith("https://")
