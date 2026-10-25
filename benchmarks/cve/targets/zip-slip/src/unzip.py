"""Extract an uploaded zip bundle into a destination directory."""

import os
import zipfile


def unzip(zip_path, dest):
    with zipfile.ZipFile(zip_path) as zf:
        for name in zf.namelist():
            target = os.path.join(dest, name)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as fh:
                fh.write(zf.read(name))
