"""Extract an uploaded tar bundle into a destination directory."""

import os
import tarfile


def extract(tar_path, dest):
    with tarfile.open(tar_path) as tf:
        tf.extractall(dest)
    return os.listdir(dest)
