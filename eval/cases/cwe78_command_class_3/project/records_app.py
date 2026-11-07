import subprocess


class Scanner:
    """Runs clamscan on files in a work folder."""

    def __init__(self, workdir):
        self.workdir = workdir

    def scan_file(self, upload):
        command = "clamscan --no-summary {}".format(upload)
        return subprocess.call(command, shell=True, cwd=self.workdir)
