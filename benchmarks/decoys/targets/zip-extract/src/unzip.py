"""Extract an uploaded zip bundle into a destination directory."""

import os
import zipfile

MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_ENTRIES = 1000
MAX_TOTAL_BYTES = 100 * 1024 * 1024
_CHUNK = 64 * 1024


class UnsafeArchive(ValueError):
    pass


def _copy_bounded(src, out, limit):
    written = 0
    while chunk := src.read(_CHUNK):
        written += len(chunk)
        if written > limit:
            raise UnsafeArchive("entry larger than declared")
        out.write(chunk)
    return written


def unzip(zip_path, dest):
    if os.path.getsize(zip_path) > MAX_ARCHIVE_BYTES:
        raise UnsafeArchive("archive too large")
    dest_real = os.path.realpath(dest)
    with zipfile.ZipFile(zip_path) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_ENTRIES:
            raise UnsafeArchive("too many entries")
        if sum(i.file_size for i in infos) > MAX_TOTAL_BYTES:
            raise UnsafeArchive("archive expands too large")
        for info in infos:
            target = os.path.realpath(os.path.join(dest_real, info.filename))
            if os.path.commonpath([dest_real, target]) != dest_real:
                raise UnsafeArchive(f"entry escapes destination: {info.filename!r}")
        for info in infos:
            target = os.path.join(dest_real, info.filename)
            if info.is_dir():
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                _copy_bounded(src, out, info.file_size)
    return sorted(os.listdir(dest_real))
