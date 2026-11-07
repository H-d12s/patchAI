import yaml

DEFAULTS = {"theme": "light", "page_size": 20}


def load_preferences(yaml_text):
    """Settings from a user's YAML file, on top of the defaults."""
    settings = dict(DEFAULTS)
    settings.update(yaml.load(yaml_text, Loader=yaml.Loader) or {})
    return settings
