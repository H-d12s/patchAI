import os


def rename_file(old_name, new_name):
    """Rename a file."""
    status = os.system("mv " + old_name + " " + new_name)
    return status == 0
