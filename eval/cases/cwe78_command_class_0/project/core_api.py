import subprocess


class Thumbnailer:
    """Runs convert on files in a work folder."""

    def __init__(self, workdir):
        self.workdir = workdir

    def make_thumbnail(self, image):
        command = "convert -thumbnail 64x64 {} thumb.png".format(image)
        return subprocess.call(command, shell=True, cwd=self.workdir)
