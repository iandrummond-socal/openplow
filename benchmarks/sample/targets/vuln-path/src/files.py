"""A deliberately vulnerable file reader (benchmark fixture)."""

import os

# Files are meant to be served only from this directory.
BASE = os.path.join(os.path.dirname(__file__), "data")


def read_file(name):
    # VULN: no path sanitisation => path traversal escapes BASE (../../secret).
    path = os.path.join(BASE, name)
    with open(path) as fh:
        return fh.read()
