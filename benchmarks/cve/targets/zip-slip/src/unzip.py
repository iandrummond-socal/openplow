"""Zip extraction — minimal reproduction of the "Zip Slip" traversal (CWE-22).

Representative advisory: Snyk "Zip Slip" (2018), the archive-extraction variant
behind many CVEs across ecosystems. Manually joining the entry name onto the
destination without validation lets a '../' entry escape the destination.
"""

import os
import zipfile


def unzip(zip_path, dest):
    with zipfile.ZipFile(zip_path) as zf:
        for name in zf.namelist():
            # VULN (Zip Slip / CWE-22): join without checking the resolved path.
            target = os.path.join(dest, name)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as fh:
                fh.write(zf.read(name))
