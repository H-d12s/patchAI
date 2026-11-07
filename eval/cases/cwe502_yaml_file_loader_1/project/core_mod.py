import yaml


class WorkflowSpec:
    """A YAML file uploaded by a user."""

    def __init__(self, path):
        self.path = path

    def load(self):
        with open(self.path, encoding="utf-8") as f:
            return yaml.load(f, Loader=yaml.Loader)
