import subprocess


class Exporter:
    """Runs libreoffice on files in a work folder."""

    def __init__(self, workdir):
        self.workdir = workdir

    def to_pdf(self, document):
        command = "libreoffice --headless --convert-to pdf {}".format(document)
        return subprocess.call(command, shell=True, cwd=self.workdir)
