import os

SNIPPETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "snippets")


def get_snippet(snippet_name):
    """Return a stored snippet."""
    with open(f"{SNIPPETS_DIR}/{snippet_name}", encoding="utf-8") as f:
        return f.read()
