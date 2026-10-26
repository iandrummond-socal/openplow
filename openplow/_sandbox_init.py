"""Launcher that runs *inside* the ``unshare`` namespaces, just before the payload.

``UnshareSandbox`` runs this file as ``python3 -I _sandbox_init.py ... -- cmd``.
It tightens the process in these steps, then ``exec``s the command:

0. Switch into a minimal root (``pivot_root``): a fresh tmpfs holding the host's
   ``/usr`` and the ``/bin /lib ...`` links read-only, a synthesised ``/etc``, an
   empty ``/tmp``, the host's ``/dev`` and ``/proc`` (steps 1 and 2 then replace
   and pin them), and each ``--rw``, ``--ro`` and ``--expose`` path at its own
   absolute path. ``$HOME``, ``/root``, ``/var``, ``/run`` ... are not in it.
   Toggled off with ``--no-minimal-root``; it requires step 1.
1. Replace ``/dev`` with a minimal tmpfs holding only ``null zero full random
   urandom tty``, a private ``devpts`` and ``/dev/shm``, and the ``fd`` and
   ``std*`` symlinks, so the host's other device nodes (``kmsg``, ``mem``,
   ``loop*`` ...) are not present. Toggled off with ``--no-minimal-dev``.
2. Harden ``/proc``: bind the subtrees that change kernel state read-only
   (``sys``, ``sysrq-trigger`` ...) and mask the parts that leak host state
   (``kcore``, ``keys`` ...). ``/proc`` itself stays writable, because
   ``/proc/self/oom_score_adj`` and ``comm`` are legitimate. ``--no-proc-harden``.
3. Make the filesystem read-only, except the paths passed with ``--rw``; then
   make the paths passed with ``--ro`` read-only again, even inside a ``--rw``
   tree (the target under test lives in the scratch dir). This also remounts the
   new ``/dev`` read-only, leaving ``/dev/shm`` and ``/dev/pts`` writable.
4. Drop every capability from the bounding set. The payload is "root" inside a
   user namespace; without this it could still remount or reconfigure things.
5. Set ``no_new_privs`` and load a seccomp denylist (mount, ptrace, bpf, module
   loading, namespace creation, io_uring and similar).
6. ``exec`` the command.

Steps 0, 1 and 2 run before step 3 so that every later step sees the final mount
tree. Each replacement is assembled in a throwaway ``tempfile.mkdtemp`` staging
dir under the first ``--rw`` path (the new root's staging dir is switched into
rather than rbound); with no ``--rw`` path to stage under, the launcher fails
closed. Nothing may be imported after step 0: the interpreter's own library may
no longer be visible, so every module the later steps use is imported up here.

Why a separate file: the mounts and the seccomp filter must go in *after* the
namespaces are set up, and the filter would block ``unshare`` and ``mount``
themselves. The file uses only the standard library and is run with ``-I`` so a
planted module in the target directory cannot be imported.

Any failure to apply a step exits 125 instead of running the payload with a
weaker sandbox than the caller asked for (125, because a shell uses 126 and 127
for "cannot execute" and "not found").

``--status-fd N`` names a pipe the parent reads to learn which steps were
applied. The launcher writes the list just before ``exec`` and closes the fd on
exec, so the payload never holds it and cannot forge a report.
"""

from __future__ import annotations

import ctypes
import os
import platform
import struct
import sys
import tempfile

# ---- mount flags (linux/mount.h) -----------------------------------------
MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_REMOUNT = 32
MS_NOATIME = 1024
MS_NODIRATIME = 2048
MS_BIND = 4096
MS_REC = 16384
MS_RELATIME = 1 << 21
MNT_DETACH = 2  # umount2(2): lazy unmount

_OPT_FLAGS = {
    "nosuid": MS_NOSUID, "nodev": MS_NODEV, "noexec": MS_NOEXEC,
    "noatime": MS_NOATIME, "nodiratime": MS_NODIRATIME, "relatime": MS_RELATIME,
}

# Mounts make_readonly leaves as they are. /proc stays writable because the payload
# legitimately writes /proc/self/oom_score_adj and /proc/self/comm; harden_proc has
# already pinned its dangerous parts read-only. /dev/shm and /dev/pts are the
# payload's own private tmpfs and devpts from minimal_dev, left writable so shared
# memory and ptys work; the rest of the new /dev IS remounted read-only, which still
# allows device writes such as /dev/null. /sys is NOT here: its cgroup filesystem is
# writable, and the payload's cgroup leaf maps to root inside the user namespace, so
# the payload could otherwise raise its own memory.max. The cgroup join happens in
# the parent, before unshare, so the payload never needs to write there.
_SKIP_PREFIXES = ("/proc", "/dev/shm", "/dev/pts")
# With the minimal root there is no /tmp, /run or /var to skip: /tmp is an empty
# read-only directory, so it is deliberately NOT listed here.

# The host directories the minimal root carries over, read-only. A merged-usr host
# has the others as symlinks into /usr, which are recreated as links.
_ROOT_DIRS = ("usr", "bin", "sbin", "lib", "lib32", "lib64", "libx32")
# Paths that are never grafted into the minimal root: they are rebuilt or absent.
_NEVER_GRAFTED = ("/proc", "/dev", "/sys")
# The only account files the payload sees; never the host's.
_ETC_FILES = {
    "passwd": "root:x:0:0:root:/tmp:/bin/sh\n"
              "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n",
    "group": "root:x:0:\nnogroup:x:65534:\n",
    "nsswitch.conf": "passwd: files\ngroup: files\nhosts: files\n",
    "hosts": "127.0.0.1 localhost\n",
}

# ---- seccomp -------------------------------------------------------------
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
PR_CAPBSET_DROP = 24
SECCOMP_MODE_FILTER = 2

SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ERRNO = 0x00050000
EPERM = 1
ENOSYS = 38

# Namespace-creating flags for clone(2): NEWNS, NEWCGROUP, NEWUTS, NEWIPC,
# NEWUSER, NEWPID, NEWNET.
CLONE_NEW_MASK = 0x00020000 | 0x02000000 | 0x04000000 | 0x08000000 | 0x10000000 \
    | 0x20000000 | 0x40000000

# BPF opcodes
_LD_W_ABS = 0x20     # BPF_LD | BPF_W | BPF_ABS
_JEQ_K = 0x15        # BPF_JMP | BPF_JEQ | BPF_K
_JGE_K = 0x35        # BPF_JMP | BPF_JGE | BPF_K
_AND_K = 0x54        # BPF_ALU | BPF_AND | BPF_K
_RET_K = 0x06        # BPF_RET | BPF_K

# arch -> (AUDIT_ARCH value, {name: syscall number}, clone nr, clone3 nr)
_COMMON = {  # same number on every 64-bit arch (new unified syscall table)
    "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
    "open_tree": 428, "move_mount": 429, "fsopen": 430, "fsconfig": 431,
    "fsmount": 432, "fspick": 433, "mount_setattr": 442,
}
_ARCHES = {
    "x86_64": (0xC000003E, {
        "ptrace": 101, "mount": 165, "umount2": 166, "pivot_root": 155, "chroot": 161,
        "reboot": 169, "swapon": 167, "swapoff": 168, "kexec_load": 246,
        "kexec_file_load": 320, "init_module": 175, "finit_module": 313,
        "delete_module": 176, "bpf": 321, "perf_event_open": 298, "keyctl": 250,
        "add_key": 248, "request_key": 249, "unshare": 272, "setns": 308,
        "process_vm_readv": 310, "process_vm_writev": 311, "userfaultfd": 323,
        "open_by_handle_at": 304, **_COMMON,
    }, 56, 435),
    "aarch64": (0xC00000B7, {
        "ptrace": 117, "mount": 40, "umount2": 39, "pivot_root": 41, "chroot": 51,
        "reboot": 142, "swapon": 224, "swapoff": 225, "kexec_load": 104,
        "kexec_file_load": 294, "init_module": 105, "finit_module": 273,
        "delete_module": 106, "bpf": 280, "perf_event_open": 241, "keyctl": 219,
        "add_key": 217, "request_key": 218, "unshare": 97, "setns": 268,
        "process_vm_readv": 270, "process_vm_writev": 271, "userfaultfd": 282,
        "open_by_handle_at": 265, **_COMMON,
    }, 220, 435),
}

# socket(2) per arch. A sibling of _ARCHES rather than a fifth tuple member, so
# existing code that unpacks the four-member tuple keeps working.
_SOCKET_NR = {"x86_64": 41, "aarch64": 198}
AF_UNIX = 1  # AF_LOCAL is the same number


def build_seccomp_program(machine: str | None = None, *, deny_unix_sockets: bool = True) -> bytes:
    """Return the classic-BPF program for ``machine`` as packed ``sock_filter``s.

    Denylist: the listed syscalls fail with EPERM; ``clone3`` fails with ENOSYS
    so libc falls back to ``clone``, whose flags are checked; ``clone`` with any
    ``CLONE_NEW*`` flag fails with EPERM; a wrong architecture is killed.
    With ``deny_unix_sockets``, ``socket(AF_UNIX, ...)`` also fails with EPERM:
    the empty network namespace does not stop filesystem sockets, and a
    read-only mount does not stop ``connect()`` on one, so this is the backstop
    for host sockets no mount hides. ``socketpair`` stays allowed, because
    multiprocessing, asyncio and subprocess rely on it.
    Raises ``RuntimeError`` on an architecture it has no table for.
    """
    machine = machine or platform.machine()
    if machine not in _ARCHES:
        raise RuntimeError(f"no seccomp table for architecture {machine!r}")
    audit_arch, names, clone_nr, clone3_nr = _ARCHES[machine]

    # Each entry: (code, jt_label|None, jf_label|None, k). Labels resolve to
    # forward offsets below, so the program stays easy to read and extend.
    prog: list[tuple[int, str | None, str | None, int]] = []
    prog.append((_LD_W_ABS, None, None, 4))                      # seccomp_data.arch
    prog.append((_JEQ_K, "load_nr", "kill", audit_arch))
    prog.append(("label", "load_nr", None, 0))                   # type: ignore[arg-type]
    prog.append((_LD_W_ABS, None, None, 0))                      # seccomp_data.nr
    if machine == "x86_64":
        prog.append((_JGE_K, "kill", None, 0x40000000))          # x32 ABI: no
    prog.append((_JEQ_K, "clone", None, clone_nr))
    prog.append((_JEQ_K, "enosys", None, clone3_nr))
    if deny_unix_sockets:
        prog.append((_JEQ_K, "sock", None, _SOCKET_NR[machine]))
    for nr in sorted(set(names.values())):
        prog.append((_JEQ_K, "eperm", None, nr))
    prog.append((_RET_K, None, None, SECCOMP_RET_ALLOW))
    prog.append(("label", "clone", None, 0))                     # type: ignore[arg-type]
    prog.append((_LD_W_ABS, None, None, 16))                     # args[0] = clone flags
    prog.append((_AND_K, None, None, CLONE_NEW_MASK))
    prog.append((_JEQ_K, "allow", "eperm", 0))
    if deny_unix_sockets:
        prog.append(("label", "sock", None, 0))                  # type: ignore[arg-type]
        prog.append((_LD_W_ABS, None, None, 16))                 # args[0] = domain
        prog.append((_JEQ_K, "eperm", "allow", AF_UNIX))
    prog.append(("label", "allow", None, 0))                     # type: ignore[arg-type]
    prog.append((_RET_K, None, None, SECCOMP_RET_ALLOW))
    prog.append(("label", "eperm", None, 0))                     # type: ignore[arg-type]
    prog.append((_RET_K, None, None, SECCOMP_RET_ERRNO | EPERM))
    prog.append(("label", "enosys", None, 0))                    # type: ignore[arg-type]
    prog.append((_RET_K, None, None, SECCOMP_RET_ERRNO | ENOSYS))
    prog.append(("label", "kill", None, 0))                      # type: ignore[arg-type]
    prog.append((_RET_K, None, None, SECCOMP_RET_KILL_PROCESS))

    # Pass 1: instruction index of every label (labels take no slot).
    index: dict[str, int] = {}
    pos = 0
    for code, jt, _jf, _k in prog:
        if code == "label":
            index[jt] = pos  # type: ignore[index]
        else:
            pos += 1

    # Pass 2: encode, turning labels into forward jump distances.
    out = bytearray()
    pos = 0
    for code, jt, jf, k in prog:
        if code == "label":
            continue
        is_jump = code in (_JEQ_K, _JGE_K)
        jt_off = jf_off = 0
        if is_jump:
            if jt is not None:
                jt_off = index[jt] - (pos + 1)
            if jf is not None:
                jf_off = index[jf] - (pos + 1)
            if not (0 <= jt_off <= 255 and 0 <= jf_off <= 255):
                raise RuntimeError("seccomp jump out of range")
        out += struct.pack("=HBBI", code, jt_off, jf_off, k)  # type: ignore[arg-type]
        pos += 1
    return bytes(out)


def _libc() -> ctypes.CDLL:
    return ctypes.CDLL(None, use_errno=True)


def _fail(msg: str) -> None:
    sys.stderr.write(f"openplow sandbox: {msg}\n")
    sys.exit(125)


def _mount(libc, source, target, fstype, flags, data=None) -> None:
    rc = libc.mount(source.encode() if source else None, target.encode(),
                    fstype.encode() if fstype else None, ctypes.c_ulong(flags),
                    data.encode() if data else None)
    if rc != 0:
        err = ctypes.get_errno()
        _fail(f"mount {target!r} (flags {flags:#x}) failed: {os.strerror(err)}")


def _unescape(path: str) -> str:
    # /proc/self/mountinfo writes space, tab, newline and backslash as \ooo.
    out, i = [], 0
    while i < len(path):
        if path[i] == "\\" and i + 3 < len(path) and path[i + 1:i + 4].isdigit():
            out.append(chr(int(path[i + 1:i + 4], 8)))
            i += 4
        else:
            out.append(path[i])
            i += 1
    return "".join(out)


def _mounts() -> list[tuple[str, int]]:
    """Return (mountpoint, preserved flag bits) for every mount, from mountinfo."""
    found = []
    with open("/proc/self/mountinfo", encoding="utf-8") as fh:
        for line in fh:
            fields = line.split()
            mountpoint = _unescape(fields[4])
            flags = 0
            for opt in fields[5].split(","):
                flags |= _OPT_FLAGS.get(opt, 0)
            found.append((mountpoint, flags))
    return found


def _within(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def make_readonly(rw_paths: list[str], ro_paths: list[str] = ()) -> None:
    """Remount every mount read-only except the ``rw_paths`` subtrees.

    A ``ro_paths`` entry is then bound onto itself and remounted read-only, so
    it stays read-only even when it sits inside a writable subtree.
    """
    libc = _libc()
    rw = [os.path.realpath(p) for p in rw_paths]
    for path in rw:  # make each a mountpoint of its own, so it can stay writable
        _mount(libc, path, path, None, MS_BIND | MS_REC)
    for mountpoint, flags in _mounts():
        if mountpoint.startswith(_SKIP_PREFIXES):
            continue
        # A mount buried under a newer one (the host's /dev/mqueue once minimal_dev
        # has rbound a fresh tree over /dev) stays in mountinfo, but its path no
        # longer exists, so it can neither be remounted nor reached by the payload.
        # Any mount still reachable by path falls through and fails closed below.
        if not os.path.lexists(mountpoint):
            continue
        if any(_within(mountpoint, p) for p in rw):
            continue
        _mount(libc, None, mountpoint, None, MS_REMOUNT | MS_BIND | MS_RDONLY | flags)
    for path in (os.path.realpath(p) for p in ro_paths):
        _mount(libc, path, path, None, MS_BIND | MS_REC)
        # Remounting an unprivileged bind must keep the flags it inherited.
        flags = max((f for m, f in _mounts() if m == path), default=0)
        _mount(libc, None, path, None, MS_REMOUNT | MS_BIND | MS_RDONLY | flags)


def _stage(scratch: str) -> str:
    """Return a fresh, tmpfs-backed staging directory under ``scratch``.

    A replacement tree is assembled here and then rbound over its target. The
    name is unique per call (``mkdtemp``), so two sandboxes sharing one scratch
    dir never collide and a directory left by a crashed run never causes EEXIST.
    Each caller uses its stage once, then detaches and removes it.

    The tmpfs is mounted ``mode=0755``, not tmpfs's default ``1777``: the stage
    becomes ``/dev`` (or ``/``), and in a sticky, world-writable directory the
    kernel refuses ``open(O_CREAT)`` on a node owned by neither the caller nor
    the directory's owner. As a non-root user the bound-in ``/dev/null`` is
    owned by the unmapped host root, so ``> /dev/null`` failed with EACCES.
    """
    try:
        stage = tempfile.mkdtemp(prefix=".openplow-stage-", dir=scratch)
    except OSError as exc:
        _fail(f"could not create a staging directory in {scratch!r}: {exc}")
    _mount(_libc(), "tmpfs", stage, "tmpfs", 0, "mode=0755")
    return stage


def _drop_stage(libc, stage: str) -> None:
    # The rbind over the target keeps its own reference to the tmpfs, so the
    # staging mountpoint can go; leftovers are harmless, so errors are ignored.
    libc.umount2(stage.encode(), MNT_DETACH)
    try:
        os.rmdir(stage)
    except OSError:
        pass


def _bind_readonly(libc, src: str, dst: str, recursive: bool = True) -> None:
    """Bind ``src`` onto ``dst`` and make it read-only at once, keeping inherited flags."""
    _mount(libc, src, dst, None, MS_BIND | (MS_REC if recursive else 0))
    # Remounting an unprivileged bind must keep the flags it inherited.
    flags = max((f for m, f in _mounts() if m == dst), default=0)
    _mount(libc, None, dst, None, MS_REMOUNT | MS_BIND | MS_RDONLY | flags)


def _check_root_paths(rw: list[str], ro: list[str],
                      expose: list[str]) -> tuple[list[str], list[str], list[str]]:
    """Validate every path before anything is created or mounted; return real paths."""
    if not rw:
        _fail("a minimal root needs a writable --rw path to stage under")
    checked: list[list[str]] = []
    for kind, raw in (("--rw", rw), ("--ro", ro), ("--expose", expose)):
        real_paths = []
        for path in raw:
            if not os.path.isabs(path):
                _fail(f"{kind} path {path!r} is not absolute")
            real = os.path.realpath(path)
            if not os.path.exists(real):
                _fail(f"{kind} path {path!r} does not exist on the host")
            if real == "/" or any(_within(real, hidden) for hidden in _NEVER_GRAFTED):
                _fail(f"{kind} path {path!r} cannot be placed in a minimal root")
            real_paths.append(real)
        checked.append(real_paths)
    rws, ros, exps = checked
    for path in rws:
        if any(_within(path, "/" + name) for name in _ROOT_DIRS):
            _fail(f"scratch {path!r} cannot live under a read-only system directory")
    for path in ros + exps:
        if any(_within(w, path) for w in rws):
            _fail(f"{path!r} is read-only but contains the writable path; it would cover it")
    return rws, ros, exps


def _write_file(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _build_etc(libc, stage: str) -> None:
    """A synthesised ``/etc``: never the host's accounts, hostname or keys."""
    etc = os.path.join(stage, "etc")
    os.mkdir(etc)
    for name, text in _ETC_FILES.items():
        _write_file(os.path.join(etc, name), text)
    if not os.path.exists("/etc/ld.so.cache"):
        _fail("no /etc/ld.so.cache; the dynamic loader would not find the libraries "
              "under /usr/lib/<triplet>")
    cache = os.path.join(etc, "ld.so.cache")
    os.close(os.open(cache, os.O_CREAT | os.O_WRONLY, 0o600))
    _bind_readonly(libc, "/etc/ld.so.cache", cache, recursive=False)
    if os.path.isdir("/etc/alternatives"):
        alternatives = os.path.join(etc, "alternatives")
        os.mkdir(alternatives)
        _bind_readonly(libc, "/etc/alternatives", alternatives)
    if os.path.exists("/usr/lib/os-release"):
        os.symlink("../usr/lib/os-release", os.path.join(etc, "os-release"))


def _graft(libc, stage: str, path: str, writable: bool) -> None:
    """Bind the host ``path`` into the new root at the same absolute path."""
    if not writable and any(_within(path, "/" + name) for name in _ROOT_DIRS):
        return  # already visible, read-only, through the system directory bind
    dst = stage + path
    if os.path.isdir(path):
        os.makedirs(dst, exist_ok=True)
    else:
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        os.close(os.open(dst, os.O_CREAT | os.O_WRONLY, 0o600))
    if writable:
        # Not recursive: the staging tmpfs is mounted inside scratch, and a recursive
        # bind of scratch would drag it into itself.
        _mount(libc, path, dst, None, MS_BIND)
    else:
        _bind_readonly(libc, path, dst)


def _build_root(libc, stage: str, rws: list[str], ros: list[str], exps: list[str]) -> None:
    for name in _ROOT_DIRS:
        src, dst = "/" + name, os.path.join(stage, name)
        if os.path.islink(src):
            os.symlink(os.readlink(src), dst)
        elif os.path.isdir(src):
            os.mkdir(dst)
            _bind_readonly(libc, src, dst)
    _build_etc(libc, stage)
    for name in ("tmp", "dev", "proc"):
        os.mkdir(os.path.join(stage, name))
    # The host's /dev and /proc; minimal_dev and harden_proc replace and pin them next.
    _mount(libc, "/proc", os.path.join(stage, "proc"), None, MS_BIND | MS_REC)
    _mount(libc, "/dev", os.path.join(stage, "dev"), None, MS_BIND | MS_REC)
    grafts = [(p, True) for p in rws] + [(p, False) for p in ros + exps]
    done: set[str] = set()
    for path, writable in sorted(grafts, key=lambda g: g[0].count("/")):  # parents first
        if path not in done:
            done.add(path)
            _graft(libc, stage, path, writable)


def minimal_root(rw: list[str], ro: list[str], expose: list[str]) -> None:
    """Replace the whole filesystem view with a small, fresh, read-only root.

    The host's ``$HOME``, ``/root``, ``/var``, ``/run``, ``/sys`` and the rest are not
    in it. The new root is assembled in a staging tmpfs under the first ``--rw`` path
    and entered with ``pivot_root(".", ".")`` followed by a lazy unmount of the old
    root, the way bubblewrap does it. Every path is validated before anything is
    created, and a failure before the switch removes the staging directory.
    """
    libc = _libc()
    rws, ros, exps = _check_root_paths(rw, ro, expose)
    machine = platform.machine()
    if machine not in _ARCHES:
        _fail(f"no pivot_root number for architecture {machine!r}")
    pivot_root_nr = _ARCHES[machine][1]["pivot_root"]
    stage = _stage(rws[0])
    try:
        try:
            _build_root(libc, stage, rws, ros, exps)
        except OSError as exc:
            _fail(f"could not build the minimal root: {exc}")
        # The staging tmpfs holds only mountpoints and generated files; scratch and any
        # other --rw path are separate mounts and stay writable.
        _mount(libc, None, stage, None, MS_REMOUNT | MS_RDONLY)
        os.chdir(stage)
        if libc.syscall(pivot_root_nr, b".", b".") != 0:
            _fail(f"pivot_root failed: {os.strerror(ctypes.get_errno())} "
                  "(the root filesystem must be a real mount, not an initramfs)")
    except BaseException:
        _drop_stage(libc, stage)
        raise
    if libc.umount2(b".", MNT_DETACH) != 0:
        _fail(f"could not detach the old root: {os.strerror(ctypes.get_errno())}")
    os.chdir("/")
    try:  # the now-empty staging mountpoint, seen through the scratch bind
        os.rmdir(os.path.join(rws[0], os.path.basename(stage)))
    except OSError:
        pass


def minimal_dev(stage: str) -> None:
    """Replace ``/dev`` with a tree holding only the nodes a payload needs.

    The host's ``/dev`` exposes ``kmsg`` (writable as real root), ``mem``,
    ``loop*``, ``fuse`` and more. The new one has six safe character devices
    bound in from the host, a private ``devpts`` and ``/dev/shm`` (so the
    payload shares neither ptys nor shared memory with the host), and the usual
    ``fd``/``std*`` symlinks. ``stage`` comes from ``_stage``.
    """
    libc = _libc()
    for node in ("null", "zero", "full", "random", "urandom", "tty"):
        dst = os.path.join(stage, node)
        try:
            os.close(os.open(dst, os.O_CREAT | os.O_WRONLY, 0o600))
        except OSError as exc:
            _fail(f"could not create {dst!r}: {exc}")
        _mount(libc, f"/dev/{node}", dst, None, MS_BIND)
    try:
        pts = os.path.join(stage, "pts")
        os.mkdir(pts)
        shm = os.path.join(stage, "shm")
        os.mkdir(shm)
        for name, link in (("fd", "/proc/self/fd"), ("stdin", "/proc/self/fd/0"),
                           ("stdout", "/proc/self/fd/1"), ("stderr", "/proc/self/fd/2"),
                           ("ptmx", "pts/ptmx")):
            os.symlink(link, os.path.join(stage, name))
    except OSError as exc:
        _fail(f"could not build the minimal /dev: {exc}")
    # A kernel may refuse a new devpts instance. Ptys are then unavailable, but the
    # rest of the minimal /dev is still far better than the host's, so skip it.
    libc.mount(b"devpts", pts.encode(), b"devpts", ctypes.c_ulong(0),
               b"newinstance,ptmxmode=0666,mode=620")
    _mount(libc, "tmpfs", shm, "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
           "mode=1777,size=64m")
    _mount(libc, stage, "/dev", None, MS_BIND | MS_REC)
    _drop_stage(libc, stage)


def harden_proc() -> None:
    """Pin the parts of ``/proc`` that change kernel state read-only; mask leaks.

    As real root, ``--map-root-user`` maps the payload onto the owner of
    ``/proc/sys`` and ``/proc/sysrq-trigger``, and the kernel checks ownership,
    not capability, so ``kernel.core_pattern`` (host-global, a code-execution
    route) would be writable. These follow the OCI runtime default lists.
    ``/proc`` itself stays writable for ``/proc/self/oom_score_adj`` and
    ``comm``. A path this kernel does not have is skipped, never an error.
    """
    libc = _libc()
    for name in ("/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"):
        path = os.path.realpath(name)
        if not os.path.exists(path):
            continue
        _mount(libc, path, path, None, MS_BIND | MS_REC)
        # Remounting an unprivileged bind must keep the flags it inherited.
        flags = max((f for m, f in _mounts() if m == path), default=0)
        _mount(libc, None, path, None, MS_REMOUNT | MS_BIND | MS_RDONLY | flags)
    for name in ("/proc/kcore", "/proc/keys", "/proc/timer_list", "/proc/sched_debug",
                 "/proc/scsi", "/proc/acpi"):
        path = os.path.realpath(name)
        if not os.path.exists(path):
            continue
        if os.path.isdir(path):
            _mount(libc, "tmpfs", path, "tmpfs", MS_RDONLY)
        else:
            _mount(libc, "/dev/null", path, None, MS_BIND)


def drop_capabilities() -> None:
    libc = _libc()
    cap = 0
    while True:
        if libc.prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0:
            if ctypes.get_errno() == 22:  # EINVAL: past the last capability
                return
            _fail(f"dropping capability {cap} failed: {os.strerror(ctypes.get_errno())}")
        cap += 1


def apply_seccomp(deny_unix_sockets: bool = True) -> None:
    libc = _libc()
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        _fail("could not set no_new_privs")
    try:
        program = build_seccomp_program(deny_unix_sockets=deny_unix_sockets)
    except RuntimeError as exc:
        _fail(str(exc))
    buf = ctypes.create_string_buffer(program, len(program))

    class SockFprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]

    fprog = SockFprog(len(program) // 8, ctypes.cast(buf, ctypes.c_void_p))
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(fprog), 0, 0) != 0:
        _fail(f"loading the seccomp filter failed: {os.strerror(ctypes.get_errno())}")


def main(argv: list[str]) -> None:
    rw: list[str] = []
    ro: list[str] = []
    expose: list[str] = []
    status_fd: int | None = None
    readonly = seccomp = True
    do_minimal_dev = do_proc_harden = do_minimal_root = True
    deny_unix_sockets = True
    i = 0
    while i < len(argv) and argv[i] != "--":
        if argv[i] == "--rw":
            rw.append(argv[i + 1])
            i += 2
        elif argv[i] == "--ro":
            ro.append(argv[i + 1])
            i += 2
        elif argv[i] == "--expose":
            expose.append(argv[i + 1])
            i += 2
        elif argv[i] == "--no-minimal-root":
            do_minimal_root = False
            i += 1
        elif argv[i] == "--status-fd":
            status_fd = int(argv[i + 1])
            i += 2
        elif argv[i] == "--no-readonly":
            readonly = False
            i += 1
        elif argv[i] == "--no-seccomp":
            seccomp = False
            i += 1
        elif argv[i] == "--no-minimal-dev":
            do_minimal_dev = False
            i += 1
        elif argv[i] == "--no-proc-harden":
            do_proc_harden = False
            i += 1
        elif argv[i] == "--allow-unix-sockets":
            deny_unix_sockets = False
            i += 1
        elif argv[i] == "--no-host-dirs":
            i += 1  # part of the launcher contract; hiding /run and /tmp is not built yet
        else:
            _fail(f"unknown option {argv[i]!r}")
    command = argv[i + 1:]
    if not command:
        _fail("no command given")

    if do_minimal_root and not do_minimal_dev:
        # With the host's /dev left in, a payload running as real root could read the
        # block devices directly, whatever the root hides.
        _fail("a minimal root needs the minimal /dev")

    applied: list[str] = []
    if do_minimal_root:
        cwd = os.getcwd()  # the switch loses it; the path exists again through its graft
        minimal_root(rw, ro, expose)
        try:
            os.chdir(cwd)
        except OSError:
            _fail(f"the working directory {cwd!r} is not inside the minimal root")
        applied.append("minimal_root")
    # /dev and /proc go first so make_readonly sees the final tree: the new /dev is
    # a fresh mount that it then remounts read-only.
    if do_minimal_dev:
        if not rw:
            _fail("a minimal /dev needs a writable --rw path to stage under")
        minimal_dev(_stage(os.path.realpath(rw[0])))
        applied.append("minimal_dev")
    if do_proc_harden:
        harden_proc()
        applied.append("proc_hardened")
    if readonly:
        cwd = os.getcwd()
        make_readonly(rw, ro)
        applied.append("readonly_fs")
        # The working directory still points at the pre-bind mount; re-enter it by
        # path so relative writes land on the writable bind.
        os.chdir(cwd)
    drop_capabilities()
    applied.append("no_capabilities")
    if seccomp:
        apply_seccomp(deny_unix_sockets)
        applied.append("seccomp")
        if deny_unix_sockets:  # the filter just loaded carries the AF_UNIX rule
            applied.append("unix_sockets_blocked")
    if status_fd is not None:
        os.set_inheritable(status_fd, False)  # closed by exec: the payload never sees it
        os.write(status_fd, ",".join(applied).encode())
    try:
        os.execvp(command[0], command)
    except OSError as exc:
        _fail(f"exec {command[0]!r} failed: {exc}")


if __name__ == "__main__":
    main(sys.argv[1:])
