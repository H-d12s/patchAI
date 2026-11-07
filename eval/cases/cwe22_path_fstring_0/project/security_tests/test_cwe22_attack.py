import os

import service_mod
from service_mod import get_snippet


def cannot_read(name):
    try:
        return "TOP SECRET" not in get_snippet(name)
    except Exception:
        return True


def test_dot_dot_cannot_escape():
    assert cannot_read("../secret.txt")


def test_absolute_path_cannot_escape():
    assert cannot_read(os.path.join(os.path.dirname(os.path.abspath(service_mod.__file__)), "secret.txt"))
