import os

REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")


def write_report(report_name, content):
    """Write a file into the output folder and return its path."""
    path = os.path.join(REPORTS_DIR, report_name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path
