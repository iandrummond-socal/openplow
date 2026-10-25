"""Sandbox hardening: seccomp program, read-only filesystem, capability drop, memory cap.

The seccomp tests run a small BPF interpreter over the generated program, so they
check behavior on any machine. The tests that start a real ``unshare`` sandbox
skip where unprivileged user namespaces are unavailable (some CI images, Docker
without ``seccomp=unconfined``).
"""

from __future__ import annotations

import struct
import subprocess
import sys
from pathlib import Path

import pytest

from openplow import _sandbox_init as init
from openplow import poc as poc_mod
from openplow.sandbox import Limits, StubSandbox, UnshareSandbox

# ---- seccomp program, checked with a tiny classic-BPF interpreter ---------

ALLOW, KILL = init.SECCOMP_RET_ALLOW, init.SECCOMP_RET_KILL_PROCESS


def _run_bpf(program: bytes, *, arch: int, nr: int, arg0: int = 0) -> int:
    insns = [struct.unpack("=HBBI", program[i:i + 8]) for i in range(0, len(program), 8)]
    data = {0: nr, 4: arch, 16: arg0 & 0xFFFFFFFF}
    acc, pc = 0, 0
    while True:
        code, jt, jf, k = insns[pc]
        pc += 1
        if code == init._LD_W_ABS:
            acc = data.get(k, 0)
        elif code == init._AND_K:
            acc &= k
        elif code == init._JEQ_K:
            pc += jt if acc == k else jf
        elif code == init._JGE_K:
            pc += jt if acc >= k else jf
        elif code == init._RET_K:
            return k
        else:
            raise AssertionError(f"unexpected opcode {code:#x}")


@pytest.mark.parametrize("machine", ["x86_64", "aarch64"])
def test_seccomp_program_behavior(machine):
    program = init.build_seccomp_program(machine)
    assert len(program) % 8 == 0
    audit_arch, names, clone_nr, clone3_nr = init._ARCHES[machine]

    def verdict(nr, arg0=0, arch=audit_arch):
        return _run_bpf(program, arch=arch, nr=nr, arg0=arg0)

    eperm = init.SECCOMP_RET_ERRNO | init.EPERM
    for name in ("mount", "ptrace", "bpf", "unshare", "setns", "init_module",
                 "io_uring_setup", "open_by_handle_at", "process_vm_writev"):
        assert verdict(names[name]) == eperm, name
    assert verdict(clone3_nr) == init.SECCOMP_RET_ERRNO | init.ENOSYS
    assert verdict(clone_nr, arg0=0x00000011) == ALLOW           # plain fork flags
    assert verdict(clone_nr, arg0=0x10000000) == eperm           # CLONE_NEWUSER
    assert verdict(clone_nr, arg0=0x40000011) == eperm           # CLONE_NEWNET
    assert verdict(0) == ALLOW                                   # an ordinary syscall
    assert verdict(names["mount"], arch=0x12345678) == KILL      # wrong architecture


def test_seccomp_x32_abi_is_killed():
    program = init.build_seccomp_program("x86_64")
    assert _run_bpf(program, arch=0xC000003E, nr=0x40000000 + 1) == KILL


def test_seccomp_unknown_architecture_fails_closed():
    with pytest.raises(RuntimeError, match="no seccomp table"):
        init.build_seccomp_program("riscv64")


def test_mountinfo_unescape_and_within():
    assert init._unescape(r"/a\040b/c") == "/a b/c"
    assert init._within("/x/y", "/x") and init._within("/x", "/x")
    assert not init._within("/xy", "/x")


# ---- memory cap -----------------------------------------------------------

def test_memory_cap_stops_a_large_allocation(tmp_path: Path):
    sb = StubSandbox(tmp_path / "sb", timeout=20, limits=Limits(cpu_seconds=20, memory_mb=256))
    res = sb.run([sys.executable, "-c", "x = bytearray(900 * 1024 * 1024); print('alloc')"])
    assert res.returncode != 0 and "MemoryError" in res.stderr


def test_unshare_sandbox_defaults_to_a_memory_cap(tmp_path: Path):
    assert UnshareSandbox(tmp_path / "a").limits.memory_mb == UnshareSandbox.default_memory_mb > 0
    assert StubSandbox(tmp_path / "b").limits.memory_mb == 0


# ---- real unshare sandbox -------------------------------------------------

def _unshare_works() -> bool:
    if not UnshareSandbox.available():
        return False
    probe = subprocess.run(
        ["unshare", "--user", "--map-root-user", "--net", "--pid", "--fork",
         "--mount-proc", "--", "true"], check=False, capture_output=True)
    return probe.returncode == 0


needs_unshare = pytest.mark.skipif(not _unshare_works(),
                                   reason="unprivileged user namespaces unavailable")


def _py(sb: UnshareSandbox, code: str, cwd=None):
    return sb.run([sys.executable, "-c", code], cwd=cwd)


@needs_unshare
def test_unshare_writes_only_inside_scratch(tmp_path: Path):
    sb = UnshareSandbox(tmp_path / "scratch", timeout=20)
    ok = _py(sb, "import os; open(os.environ['TMPDIR'] + '/f', 'w').write('1'); print('ok')")
    assert ok.returncode == 0, ok.stderr
    assert (tmp_path / "scratch" / "f").read_text() == "1"

    outside = tmp_path / "outside.txt"
    bad = _py(sb, f"open({str(outside)!r}, 'w').write('x')")
    assert bad.returncode != 0 and "Read-only file system" in bad.stderr
    assert not outside.exists()
    etc = _py(sb, "open('/etc/openplow-test', 'w')")
    assert etc.returncode != 0 and "Read-only file system" in etc.stderr


@needs_unshare
def test_unshare_cwd_outside_scratch_is_writable_only_for_that_dir(tmp_path: Path):
    work = tmp_path / "work"
    work.mkdir()
    sb = UnshareSandbox(tmp_path / "scratch", timeout=20)
    res = _py(sb, "open('made', 'w').write('1')", cwd=work)
    assert res.returncode == 0, res.stderr
    assert (work / "made").exists()
    sibling = _py(sb, f"open({str(tmp_path / 'sibling')!r}, 'w')", cwd=work)
    assert sibling.returncode != 0


@needs_unshare
def test_unshare_drops_capabilities_and_blocks_syscalls(tmp_path: Path):
    sb = UnshareSandbox(tmp_path / "scratch", timeout=20)
    caps = _py(sb, "print(open('/proc/self/status').read().split('CapEff:')[1].split()[0])")
    assert caps.stdout.strip() == "0" * 16
    code = (
        "import ctypes, errno\n"
        "l = ctypes.CDLL(None, use_errno=True)\n"
        "print(l.mount(b'none', b'/mnt', b'tmpfs', 0, None), ctypes.get_errno() == errno.EPERM)\n"
        "print(l.unshare(0x10000000), ctypes.get_errno() == errno.EPERM)\n"
        "print(l.ptrace(0, 0, 0, 0), ctypes.get_errno() == errno.EPERM)\n"
    )
    res = _py(sb, code)
    assert res.stdout.split() == ["-1", "True"] * 3, res.stderr


@needs_unshare
def test_unshare_still_runs_normal_programs(tmp_path: Path):
    sb = UnshareSandbox(tmp_path / "scratch", timeout=20)
    code = ("import subprocess, threading\n"
            "t = threading.Thread(target=lambda: print('thread')); t.start(); t.join()\n"
            "print(subprocess.run(['echo', 'child'], capture_output=True, text=True).stdout)\n")
    res = _py(sb, code)
    assert res.returncode == 0, res.stderr
    assert "thread" in res.stdout and "child" in res.stdout


@needs_unshare
def test_unshare_blocks_network(tmp_path: Path):
    sb = UnshareSandbox(tmp_path / "scratch", timeout=20)
    res = _py(sb, "import socket; socket.create_connection(('1.1.1.1', 53), 2)")
    assert res.returncode != 0


@needs_unshare
def test_unshare_fails_closed_when_setup_fails(tmp_path: Path):
    # A step that cannot be applied must stop the run, not run the payload unhardened.
    sb = UnshareSandbox(tmp_path / "scratch", timeout=20)
    marker = tmp_path / "ran"
    argv = sb._wrap([sys.executable, "-c", f"open({str(marker)!r}, 'w')"])
    argv[argv.index("--rw") + 1] = str(tmp_path / "does-not-exist")
    res = subprocess.run(argv, check=False, capture_output=True, text=True)
    assert res.returncode == 126 and "openplow sandbox" in res.stderr
    assert not marker.exists()


@needs_unshare
def test_poc_runs_in_hardened_sandbox_and_flags_tampering(tmp_path: Path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "app.py").write_text("x = 1\n")
    sb = UnshareSandbox(tmp_path / "scratch", timeout=20)

    good = {"poc": {"kind": "script", "content": "print('PWNED')\n", "observed": "PWNED"}}
    run = poc_mod.run_poc(sb, repo, good, tmp_path / "scratch" / "f1")
    assert run.attempted and run.demonstrated and run.integrity_ok, run.output

    tamper = {"poc": {"kind": "script",
                      "content": "open('src/app.py', 'w').write('tampered')\n"}}
    run = poc_mod.run_poc(sb, repo, tamper, tmp_path / "scratch" / "f2")
    assert not run.demonstrated
