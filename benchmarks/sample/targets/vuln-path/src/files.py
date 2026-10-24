"""A deliberately vulnerable file reader (benchmark fixture)."""

import os

BASE = "/srv/data"


def read_file(name):
    # VULN: no path sanitisation => path traversal (../../etc/passwd).
    path = os.path.join(BASE, name)
    with open(path) as fh:
        return fh.read()
