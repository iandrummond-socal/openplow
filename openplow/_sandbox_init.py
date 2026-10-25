"""Launcher that runs *inside* the ``unshare`` namespaces, just before the payload.

``UnshareSandbox`` runs this file as ``python3 -I _sandbox_init.py ... -- cmd``.
It tightens the process in four steps, then ``exec``s the command:

1. Make the filesystem read-only, except the paths passed with ``--rw``; then
   make the paths passed with ``--ro`` read-only again, even inside a ``--rw``
   tree (the target under test lives in the scratch dir).
2. Drop every capability from the bounding set. The payload is "root" inside a
   user namespace; without this it could still remount or reconfigure things.
3. Set ``no_new_privs`` and load a seccomp denylist (mount, ptrace, bpf, module
   loading, namespace creation, io_uring and similar).
4. ``exec`` the command.

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

_OPT_FLAGS = {
    "nosuid": MS_NOSUID, "nodev": MS_NODEV, "noexec": MS_NOEXEC,
    "noatime": MS_NOATIME, "nodiratime": MS_NODIRATIME, "relatime": MS_RELATIME,
}

# Mounts that are not part of the file tree a payload could write source into.
_SKIP_PREFIXES = ("/proc", "/sys", "/dev")

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


def build_seccomp_program(machine: str | None = None) -> bytes:
    """Return the classic-BPF program for ``machine`` as packed ``sock_filter``s.

    Denylist: the listed syscalls fail with EPERM; ``clone3`` fails with ENOSYS
    so libc falls back to ``clone``, whose flags are checked; ``clone`` with any
    ``CLONE_NEW*`` flag fails with EPERM; a wrong architecture is killed.
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
    for nr in sorted(set(names.values())):
        prog.append((_JEQ_K, "eperm", None, nr))
    prog.append((_RET_K, None, None, SECCOMP_RET_ALLOW))
    prog.append(("label", "clone", None, 0))                     # type: ignore[arg-type]
    prog.append((_LD_W_ABS, None, None, 16))                     # args[0] = clone flags
    prog.append((_AND_K, None, None, CLONE_NEW_MASK))
    prog.append((_JEQ_K, "allow", "eperm", 0))
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


def _mount(libc, source, target, fstype, flags) -> None:
    rc = libc.mount(source.encode() if source else None, target.encode(),
                    fstype.encode() if fstype else None, ctypes.c_ulong(flags), None)
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
        if any(_within(mountpoint, p) for p in rw):
            continue
        _mount(libc, None, mountpoint, None, MS_REMOUNT | MS_BIND | MS_RDONLY | flags)
    for path in (os.path.realpath(p) for p in ro_paths):
        _mount(libc, path, path, None, MS_BIND | MS_REC)
        # Remounting an unprivileged bind must keep the flags it inherited.
        flags = max((f for m, f in _mounts() if m == path), default=0)
        _mount(libc, None, path, None, MS_REMOUNT | MS_BIND | MS_RDONLY | flags)


def drop_capabilities() -> None:
    libc = _libc()
    cap = 0
    while True:
        if libc.prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0:
            if ctypes.get_errno() == 22:  # EINVAL: past the last capability
                return
            _fail(f"dropping capability {cap} failed: {os.strerror(ctypes.get_errno())}")
        cap += 1


def apply_seccomp() -> None:
    libc = _libc()
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        _fail("could not set no_new_privs")
    try:
        program = build_seccomp_program()
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
    status_fd: int | None = None
    readonly = seccomp = True
    i = 0
    while i < len(argv) and argv[i] != "--":
        if argv[i] == "--rw":
            rw.append(argv[i + 1])
            i += 2
        elif argv[i] == "--ro":
            ro.append(argv[i + 1])
            i += 2
        elif argv[i] == "--status-fd":
            status_fd = int(argv[i + 1])
            i += 2
        elif argv[i] == "--no-readonly":
            readonly = False
            i += 1
        elif argv[i] == "--no-seccomp":
            seccomp = False
            i += 1
        else:
            _fail(f"unknown option {argv[i]!r}")
    command = argv[i + 1:]
    if not command:
        _fail("no command given")

    applied: list[str] = []
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
        apply_seccomp()
        applied.append("seccomp")
    if status_fd is not None:
        os.set_inheritable(status_fd, False)  # closed by exec: the payload never sees it
        os.write(status_fd, ",".join(applied).encode())
    try:
        os.execvp(command[0], command)
    except OSError as exc:
        _fail(f"exec {command[0]!r} failed: {exc}")


if __name__ == "__main__":
    main(sys.argv[1:])
