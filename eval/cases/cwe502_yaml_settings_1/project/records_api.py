import yaml

DEFAULTS = {"theme": "light", "page_size": 20}


def read_profile(document):
    """Settings from a user's YAML file, on top of the defaults."""
    settings = dict(DEFAULTS)
    settings.update(yaml.load(document, Loader=yaml.Loader) or {})
    return settings
