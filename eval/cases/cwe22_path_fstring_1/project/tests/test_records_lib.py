import pytest

from records_lib import get_snippet


def test_reads_a_stored_file():
    assert "Welcome" in get_snippet("welcome.txt")


def test_missing_file_raises():
    with pytest.raises(OSError):
        get_snippet("missing.txt")
