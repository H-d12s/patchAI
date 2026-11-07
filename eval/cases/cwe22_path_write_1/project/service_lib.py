import os

EXPORT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")


def save_export(filename, content):
    """Write a file into the output folder and return its path."""
    path = os.path.join(EXPORT_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path
