"""Extract an uploaded tar bundle into a destination directory."""

import os
import shutil
import tarfile

MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_MEMBERS = 1000
MAX_TOTAL_BYTES = 100 * 1024 * 1024


class UnsafeArchive(ValueError):
    pass


def _check(members, dest_real):
    if len(members) > MAX_MEMBERS:
        raise UnsafeArchive("too many members")
    total = 0
    for m in members:
        if not (m.isfile() or m.isdir()):
            raise UnsafeArchive(f"unsupported member type: {m.name!r}")
        target = os.path.realpath(os.path.join(dest_real, m.name))
        if os.path.commonpath([dest_real, target]) != dest_real:
            raise UnsafeArchive(f"member escapes destination: {m.name!r}")
        total += m.size
        if total > MAX_TOTAL_BYTES:
            raise UnsafeArchive("archive expands too large")


def extract(tar_path, dest):
    if os.path.getsize(tar_path) > MAX_ARCHIVE_BYTES:
        raise UnsafeArchive("archive too large")
    dest_real = os.path.realpath(dest)
    # "r:" accepts only uncompressed tar, so the archive size bounds the work.
    with tarfile.open(tar_path, "r:") as tf:
        members = tf.getmembers()
        _check(members, dest_real)
        for m in members:
            target = os.path.join(dest_real, m.name)
            if m.isdir():
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            src = tf.extractfile(m)
            with src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)
    return os.listdir(dest_real)
