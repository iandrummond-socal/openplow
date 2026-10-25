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
import time
from pathlib import Path

import pytest

from openplow import _sandbox_init as init
from openplow import poc as poc_mod
from openplow import sandbox as sandbox_mod
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

@pytest.mark.skipif(sys.platform == "darwin",
                    reason="macOS does not enforce RLIMIT_DATA; the cap is Linux-only")
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
@pytest.mark.parametrize("inside_scratch", [True, False])
def test_unshare_cwd_is_read_only(tmp_path: Path, inside_scratch: bool):
    # The PoC's working directory is the target under test: it can read it but
    # not change it, whether it sits inside the scratch dir (the real pipeline)
    # or beside it. Scratch itself, outside the target, stays writable.
    scratch = tmp_path / "scratch"
    target = (scratch if inside_scratch else tmp_path) / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "app.py").write_text("x = 1\n")
    sb = UnshareSandbox(scratch, timeout=20)

    read = _py(sb, "print(open('src/app.py').read().strip())", cwd=target)
    assert read.returncode == 0 and read.stdout.strip() == "x = 1", read.stderr

    for code in ("open('src/app.py', 'w').write('tampered')",   # overwrite existing
                 "open('new.py', 'w').write('x')",              # create a file
                 "import os; os.mkdir('d')",                    # create a dir
                 "import os; os.remove('src/app.py')"):         # delete
        res = _py(sb, code, cwd=target)
        assert res.returncode != 0 and "Read-only file system" in res.stderr, code
    assert sorted(p.name for p in target.iterdir()) == ["src"]
    assert (target / "src" / "app.py").read_text() == "x = 1\n"

    ok = _py(sb, "import os; open(os.environ['TMPDIR'] + '/f', 'w').write('1')", cwd=target)
    assert ok.returncode == 0, ok.stderr
    assert (scratch / "f").read_text() == "1"


@needs_unshare
def test_unshare_cannot_remount_target_writable(tmp_path: Path):
    target = tmp_path / "scratch" / "target"
    target.mkdir(parents=True)
    sb = UnshareSandbox(tmp_path / "scratch", timeout=20)
    code = ("import ctypes\n"
            "l = ctypes.CDLL(None, use_errno=True)\n"
            "print(l.mount(None, str(__import__('os').getcwd()).encode(), None, 32 | 4096, None))\n"
            "open('x', 'w')\n")
    res = _py(sb, code, cwd=target)
    assert res.returncode != 0 and not (target / "x").exists()


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
    assert res.returncode == 125 and "openplow sandbox" in res.stderr
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
    assert "Read-only file system" in run.output  # blocked outright, not just detected
    assert run.integrity_ok


@needs_unshare
def test_enforced_reports_every_protection_on_a_normal_run(tmp_path: Path):
    res = _py(UnshareSandbox(tmp_path / "scratch", timeout=20), "print('hi')")
    assert res.returncode == 0, res.stderr
    # memory_cap (the cgroup) depends on the host delegating one; the rest never does.
    assert {k: v for k, v in res.enforced.items() if k != "memory_cap"} == {
        "network_isolated": True, "readonly_fs": True, "no_capabilities": True,
        "seccomp": True, "heap_limit": True}
    assert res.enforced["memory_cap"] is (sandbox_mod._cgroup_parent() is not None)


@needs_unshare
def test_enforced_is_honest_when_a_protection_is_off(tmp_path: Path):
    sb = UnshareSandbox(tmp_path / "scratch", timeout=20, seccomp=False)
    res = _py(sb, "print('hi')")
    assert res.returncode == 0, res.stderr
    assert res.enforced["seccomp"] is False and res.enforced["readonly_fs"] is True


@needs_unshare
def test_enforced_is_all_false_when_the_launcher_fails(tmp_path: Path):
    class Broken(UnshareSandbox):
        def _wrap(self, argv, cwd=None, status_fd=None):
            out = super()._wrap(argv, cwd, status_fd)
            out[out.index("--rw") + 1] = str(tmp_path / "does-not-exist")
            return out

    res = _py(Broken(tmp_path / "scratch", timeout=20), "print('ran')")
    assert res.returncode == 125 and "openplow sandbox" in res.stderr
    assert "ran" not in res.stdout
    assert res.enforced and not any(res.enforced.values())


@needs_unshare
def test_payload_cannot_forge_the_status_report(tmp_path: Path):
    # The report fd is closed on exec: the payload finds nothing to write to.
    code = ("import os\n"
            "for fd in range(3, 64):\n"
            "    try: os.write(fd, b'readonly_fs,no_capabilities,seccomp')\n"
            "    except OSError: pass\n"
            "raise SystemExit(125)\n")
    sb = UnshareSandbox(tmp_path / "scratch", timeout=20)
    res = _py(sb, code)
    assert res.returncode == 125
    assert not any(res.enforced.values())  # cautious, never more generous


def test_stub_sandbox_claims_nothing(tmp_path: Path):
    res = StubSandbox(tmp_path / "sb", timeout=20).run([sys.executable, "-c", "pass"])
    assert res.enforced == {}


@needs_unshare
def test_timed_out_payload_leaves_no_running_children(tmp_path: Path):
    ticks = tmp_path / "scratch" / "ticks"
    code = ("import os, subprocess, sys, time\n"
            "subprocess.Popen([sys.executable, '-c', 'import os, time\\n"
            "while True:\\n"
            "    open(os.environ[\"TMPDIR\"] + \"/ticks\", \"a\").write(\"x\")\\n"
            "    time.sleep(0.1)'])\n"
            "time.sleep(60)\n")
    sb = UnshareSandbox(tmp_path / "scratch", timeout=2)
    res = _py(sb, code)
    assert res.timed_out
    size = ticks.stat().st_size
    time.sleep(1)
    assert ticks.stat().st_size == size  # the child stopped with its parent


def test_poc_run_on_the_stub_claims_no_protections(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    finding = {"poc": {"kind": "script", "content": "print('PWNED')\n", "observed": "PWNED"}}
    run = poc_mod.run_poc(StubSandbox(tmp_path / "sb", timeout=20), repo, finding,
                          tmp_path / "sb" / "f")
    assert run.demonstrated and run.enforced == {}


@needs_unshare
def test_poc_run_reports_the_protections_that_ran(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    finding = {"poc": {"kind": "script", "content": "print('PWNED')\n", "observed": "PWNED"}}
    sb = UnshareSandbox(tmp_path / "scratch", timeout=20)
    run = poc_mod.run_poc(sb, repo, finding, tmp_path / "scratch" / "f")
    assert run.demonstrated, run.output
    assert run.enforced["readonly_fs"] and run.enforced["seccomp"]
    assert run.enforced["no_capabilities"] and run.enforced["network_isolated"]


# ---- cgroup-v2 memory cap --------------------------------------------------
# These need a delegated cgroup with the memory controller; scripts/test_linux.sh
# sets one up. Elsewhere they skip, and the honest-fallback tests still run.

needs_cgroup = pytest.mark.skipif(
    not (_unshare_works() and sandbox_mod._cgroup_parent() is not None),
    reason="no delegated cgroup with the memory controller")

# A shared mapping is charged to the cgroup but not counted by RLIMIT_DATA, so
# only the cgroup cap can stop it.
_BOMB = ("import mmap\n"
         "m = mmap.mmap(-1, 900 * 1024 * 1024)\n"
         "for i in range(0, len(m), 4096):\n"
         "    m[i] = 1\n"
         "print('survived')\n")


def _leaves() -> list[Path]:
    parent = sandbox_mod._cgroup_parent()
    return sorted(parent.glob("openplow-*")) if parent else []


@needs_cgroup
def test_cgroup_cap_kills_a_memory_bomb(tmp_path: Path):
    sb = UnshareSandbox(tmp_path / "scratch", timeout=30, limits=Limits(memory_mb=128))
    start = time.monotonic()
    res = _py(sb, _BOMB)
    assert "survived" not in res.stdout and res.returncode != 0
    assert res.oom_killed and res.enforced["memory_cap"] is True
    assert time.monotonic() - start < 20
    assert _leaves() == []


@needs_cgroup
def test_cgroup_cap_leaves_a_normal_payload_alone(tmp_path: Path):
    sb = UnshareSandbox(tmp_path / "scratch", timeout=30, limits=Limits(memory_mb=512))
    res = _py(sb, "x = bytearray(50 * 1024 * 1024); print('fine')")
    assert res.returncode == 0 and "fine" in res.stdout, res.stderr
    assert not res.oom_killed and res.enforced["memory_cap"] is True
    assert _leaves() == []


@needs_cgroup
def test_cgroup_leaf_is_removed_after_a_timeout(tmp_path: Path):
    sb = UnshareSandbox(tmp_path / "scratch", timeout=2, limits=Limits(memory_mb=512))
    res = _py(sb, "import time; time.sleep(60)")
    assert res.timed_out and _leaves() == []


@needs_cgroup
def test_cgroup_cold_start_twin(tmp_path: Path):
    # First run and a repeat run both get a fresh leaf and clean up.
    sb = UnshareSandbox(tmp_path / "scratch", timeout=30, limits=Limits(memory_mb=512))
    for _ in range(2):
        res = _py(sb, "print('ok')")
        assert res.returncode == 0 and res.enforced["memory_cap"] is True
        assert _leaves() == []


@needs_unshare
def test_memory_cap_is_reported_false_when_no_cgroup(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setattr(sandbox_mod, "_cgroup_parent", lambda *a, **k: None)
    monkeypatch.setattr(sandbox_mod, "_warned_no_cgroup", False)
    sb = UnshareSandbox(tmp_path / "scratch", timeout=20, limits=Limits(memory_mb=512))
    for _ in range(2):
        res = _py(sb, "print('ran')")
        assert res.returncode == 0 and "ran" in res.stdout
        assert res.enforced["memory_cap"] is False and res.enforced["heap_limit"] is True
        assert res.oom_killed is False
    assert capsys.readouterr().err.count("no memory cap from a cgroup") == 1  # warned once


@needs_unshare
def test_no_cgroup_is_made_when_the_cap_is_off(tmp_path: Path, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("a cgroup was requested with memory_mb=0")
    monkeypatch.setattr(sandbox_mod, "_make_cgroup_leaf", boom)
    sb = UnshareSandbox(tmp_path / "scratch", timeout=20, limits=Limits(memory_mb=0))
    res = _py(sb, "print('ok')")
    assert res.returncode == 0
    assert res.enforced["memory_cap"] is False and res.enforced["heap_limit"] is False


def test_cgroup_parent_picks_a_delegated_writable_cgroup(tmp_path: Path):
    root = tmp_path / "cg"
    (root / "a" / "b").mkdir(parents=True)
    (root / "cgroup.controllers").write_text("memory\n")
    proc = tmp_path / "proc_cgroup"
    proc.write_text("0::/a/b\n")
    # Neither /a/b nor /a delegates memory: no cap.
    (root / "a" / "b" / "cgroup.subtree_control").write_text("")
    (root / "a" / "cgroup.subtree_control").write_text("cpu\n")
    assert sandbox_mod._cgroup_parent(root, proc) is None
    # The parent delegates memory: a sibling leaf under it is fine.
    (root / "a" / "cgroup.subtree_control").write_text("cpu memory\n")
    assert sandbox_mod._cgroup_parent(root, proc) == root / "a"
    # Its own delegation wins.
    (root / "a" / "b" / "cgroup.subtree_control").write_text("memory\n")
    assert sandbox_mod._cgroup_parent(root, proc) == root / "a" / "b"
    # Not cgroup v2 (no cgroup.controllers): no cap.
    (root / "cgroup.controllers").unlink()
    assert sandbox_mod._cgroup_parent(root, proc) is None


@needs_cgroup
def test_payload_cannot_lift_its_own_memory_cap(tmp_path: Path):
    # The leaf's files map to the payload's root inside the user namespace, so the
    # cgroup filesystem must be read-only there or the payload can write memory.max.
    code = ("import os\n"
            "rel = open('/proc/self/cgroup').read().strip().split('::', 1)[1]\n"
            "try:\n"
            "    open('/sys/fs/cgroup' + rel + '/memory.max', 'w').write('max')\n"
            "    print('LIFTED')\n"
            "except OSError as e:\n"
            "    print('blocked', e.errno)\n")
    sb = UnshareSandbox(tmp_path / "scratch", timeout=30, limits=Limits(memory_mb=128))
    res = _py(sb, code)
    assert "LIFTED" not in res.stdout and "blocked" in res.stdout, res.stdout + res.stderr
    # ...and the cap still bites after the attempt.
    res = _py(sb, _BOMB)
    assert res.oom_killed and "survived" not in res.stdout
