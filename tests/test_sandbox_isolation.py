"""Sandbox isolation: PoCs that try to reach outside the sandbox and must fail.

``test_sandbox_hardening.py`` checks the pieces (the seccomp program, the status
report). These tests are the other half: each one runs a small hostile program
inside a real ``unshare`` sandbox and asserts that the thing it reaches for is out
of reach, so a regression in the launcher shows up as a PoC that got through.

Where a protection can be switched off, a twin test switches it off and shows the
same PoC getting through. A twin that cannot get through (the host does not have
the file, the user is not root) skips, so a passing protection test always means
the PoC was able to succeed without the protection.

They need a Linux kernel with unprivileged user namespaces, so on macOS they skip.
Run them with ``scripts/test_linux.sh tests/test_sandbox_isolation.py``, and again
with ``OPENPLOW_TEST_USER=1000`` to prove nothing relies on the caller being root.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest
from test_sandbox_hardening import _py, _unshare_works, needs_unshare

from openplow.sandbox import UnshareSandbox

AS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0

# The nodes minimal_dev builds, and the ones a hostile PoC would want from the host.
EXPECTED_DEV = {"null", "zero", "full", "random", "urandom", "tty",
                "pts", "shm", "fd", "stdin", "stdout", "stderr", "ptmx"}
HOST_ONLY_DEV = ("kmsg", "mem", "kmem", "port", "fuse")


def _sandbox(tmp_path: Path, **kwargs) -> UnshareSandbox:
    return UnshareSandbox(tmp_path / "scratch", timeout=20, **kwargs)


# A write that would change the host if it got through. Each rewrites a value with
# itself (or only opens for writing), so even a protection failure changes nothing.
_KERNEL_WRITES = (
    "import errno, sys\n"
    "def attempt(path, mode, data=None):\n"
    "    try:\n"
    "        with open(path, mode) as f:\n"
    "            if data is not None:\n"
    "                f.write(data)\n"
    "        return 'WRITABLE'\n"
    "    except OSError as e:\n"
    "        return errno.errorcode.get(e.errno, str(e.errno))\n"
    "hostname = open('/proc/sys/kernel/hostname').read()\n"
    "core = open('/proc/sys/kernel/core_pattern').read()\n"
    "print('hostname', attempt('/proc/sys/kernel/hostname', 'w', hostname))\n"
    "print('core_pattern', attempt('/proc/sys/kernel/core_pattern', 'w', core))\n"
    "print('sysrq', attempt('/proc/sysrq-trigger', 'w'))\n"
)


def _kernel_writes(res) -> dict[str, str]:
    assert res.returncode == 0, res.stderr
    return dict(line.split() for line in res.stdout.splitlines())


@needs_unshare
def test_kernel_settings_cannot_be_written(tmp_path: Path):
    # core_pattern is host-global and a known code-execution route.
    out = _kernel_writes(_py(_sandbox(tmp_path), _KERNEL_WRITES))
    assert out == {"hostname": "EROFS", "core_pattern": "EROFS", "sysrq": "EROFS"}


@needs_unshare
@pytest.mark.skipif(not AS_ROOT, reason="only real root can write these files unprotected")
def test_kernel_settings_twin_writable_without_proc_hardening(tmp_path: Path):
    sb = _sandbox(tmp_path, harden_proc=False)
    out = _kernel_writes(_py(sb, _KERNEL_WRITES))
    if out["core_pattern"] != "WRITABLE":
        pytest.skip("this kernel does not let even root write /proc/sys here")
    assert out["hostname"] == "WRITABLE" and out["core_pattern"] == "WRITABLE"


@needs_unshare
@pytest.mark.parametrize("path", ["/proc/kcore", "/proc/keys", "/proc/timer_list"])
def test_proc_leaks_are_masked(tmp_path: Path, path: str):
    if not Path(path).exists():
        pytest.skip(f"{path} does not exist on this kernel")
    res = _py(_sandbox(tmp_path), f"print(len(open({path!r}, 'rb').read(4096)))")
    # Bound over /dev/null: it opens, and yields nothing.
    assert res.returncode == 0 and res.stdout.strip() == "0", res.stderr


@needs_unshare
def test_proc_still_serves_what_a_payload_needs(tmp_path: Path):
    code = ("open('/proc/self/oom_score_adj', 'w').write('500')\n"
            "print(open('/proc/self/oom_score_adj').read().strip())\n"
            "print(open('/proc/self/comm').read().strip() != '')\n"
            "print(open('/proc/self/cmdline', 'rb').read() != b'')\n")
    res = _py(_sandbox(tmp_path), code)
    assert res.returncode == 0, res.stderr
    assert res.stdout.split() == ["500", "True", "True"]


# ---- /dev --------------------------------------------------------------------

@needs_unshare
def test_dev_holds_only_the_minimal_nodes(tmp_path: Path):
    res = _py(_sandbox(tmp_path), "import os; print(*sorted(os.listdir('/dev')))")
    assert res.returncode == 0, res.stderr
    assert set(res.stdout.split()) == EXPECTED_DEV


@needs_unshare
def test_dev_hides_host_devices(tmp_path: Path):
    present = [n for n in HOST_ONLY_DEV if Path("/dev", n).exists()]
    if not present:
        pytest.skip("the host has none of the devices a PoC would reach for")
    code = ("import os\n"
            f"print(*[n for n in {present!r} if os.path.lexists('/dev/' + n)])\n")
    res = _py(_sandbox(tmp_path), code)
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip() == ""


@needs_unshare
def test_dev_twin_shows_host_devices_without_minimal_dev(tmp_path: Path):
    present = [n for n in HOST_ONLY_DEV if Path("/dev", n).exists()]
    if not present:
        pytest.skip("the host has none of the devices a PoC would reach for")
    code = f"import os; print(*[n for n in {present!r} if os.path.lexists('/dev/' + n)])"
    res = _py(_sandbox(tmp_path, minimal_dev=False), code)
    assert res.returncode == 0, res.stderr
    assert res.stdout.split() == present


@needs_unshare
def test_dev_nodes_work_and_the_tree_is_read_only(tmp_path: Path):
    code = ("import os\n"
            "print(os.read(os.open('/dev/urandom', os.O_RDONLY), 8) != b'')\n"
            "print(os.read(os.open('/dev/zero', os.O_RDONLY), 4) == b'\\0' * 4)\n"
            "os.write(os.open('/dev/null', os.O_WRONLY), b'discarded')\n"
            "print('null ok')\n"
            "try:\n"
            "    open('/dev/new-node', 'w')\n"
            "except OSError as e:\n"
            "    print('dev', e.strerror)\n")
    res = _py(_sandbox(tmp_path), code)
    assert res.returncode == 0, res.stderr
    assert res.stdout.splitlines() == ["True", "True", "null ok", "dev Read-only file system"]


@needs_unshare
@pytest.mark.xfail(
    not AS_ROOT, strict=True,
    reason="known bug: as a non-root user the minimal /dev refuses open(O_CREAT) on its "
           "nodes, so `> /dev/null` fails with EACCES. Bisected to minimal_dev (it passes "
           "with minimal_dev=False); root is unaffected. Tracked in docs/HANDOFF.md.")
def test_dev_null_can_be_redirected_to(tmp_path: Path):
    # What a shell's `> /dev/null` and Python's open('/dev/null', 'w') both do.
    res = _py(_sandbox(tmp_path), "open('/dev/null', 'w').write('discarded'); print('ok')")
    assert res.returncode == 0 and res.stdout.strip() == "ok", res.stderr


@needs_unshare
def test_dev_shm_is_private_and_writable(tmp_path: Path):
    shm = Path("/dev/shm")
    if not shm.is_dir() or not os.access(shm, os.W_OK):
        pytest.skip("the host has no writable /dev/shm to leak from")
    marker = shm / f"openplow-isolation-{os.getpid()}"
    marker.write_text("host")
    try:
        code = ("import os\n"
                f"print(os.path.exists({str(marker)!r}))\n"
                "open('/dev/shm/mine', 'w').write('x')\n"
                "print('wrote')\n")
        res = _py(_sandbox(tmp_path), code)
        assert res.returncode == 0, res.stderr
        assert res.stdout.split() == ["False", "wrote"]
        assert not (shm / "mine").exists()  # nothing the PoC wrote reached the host
    finally:
        marker.unlink(missing_ok=True)


# ---- unix sockets -------------------------------------------------------------

def _connect_code(path: Path) -> str:
    return ("import errno, socket\n"
            "try:\n"
            "    s = socket.socket(socket.AF_UNIX)\n"
            f"    s.connect({str(path)!r})\n"
            "    print('CONNECTED')\n"
            "except OSError as e:\n"
            "    print(errno.errorcode.get(e.errno, str(e.errno)))\n")


@pytest.fixture
def host_socket(tmp_path: Path):
    """A unix socket listening on the host side: stands in for DBus, docker.sock, ..."""
    # AF_UNIX paths are short (~104 bytes), so keep it directly under tmp_path.
    path = tmp_path / "host.sock"
    server = socket.socket(socket.AF_UNIX)
    server.bind(str(path))
    server.listen(1)
    try:
        yield path
    finally:
        server.close()


@needs_unshare
def test_unix_sockets_are_refused_by_default(tmp_path: Path, host_socket: Path):
    res = _py(_sandbox(tmp_path), _connect_code(host_socket))
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip() == "EPERM"  # refused at socket(), before any connect


@needs_unshare
def test_unix_socket_twin_connects_when_opted_in(tmp_path: Path, host_socket: Path):
    # The documented limit: with allow_unix_sockets=True a socket the sandbox can
    # see is reachable. Hiding /run and /tmp narrows what it can see; it is the
    # reason this stays off by default.
    res = _py(_sandbox(tmp_path, allow_unix_sockets=True), _connect_code(host_socket))
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip() == "CONNECTED"


@needs_unshare
def test_unix_socket_opt_in_serves_a_payload_that_needs_one(tmp_path: Path):
    code = ("import os, socket\n"
            "p = os.environ['TMPDIR'] + '/s.sock'\n"
            "srv = socket.socket(socket.AF_UNIX); srv.bind(p); srv.listen(1)\n"
            "cli = socket.socket(socket.AF_UNIX); cli.connect(p)\n"
            "conn, _ = srv.accept(); cli.sendall(b'ping')\n"
            "print(conn.recv(4).decode())\n")
    sb = _sandbox(tmp_path, allow_unix_sockets=True)
    res = _py(sb, code)
    assert res.returncode == 0 and res.stdout.strip() == "ping", res.stderr
    blocked = _py(_sandbox(tmp_path), code)
    assert blocked.returncode != 0 and "Operation not permitted" in blocked.stderr


@needs_unshare
def test_socketpair_and_other_families_still_work_by_default(tmp_path: Path):
    # multiprocessing, asyncio and subprocess all use socketpair; AF_INET is still
    # creatable (the empty network namespace is what stops traffic, not seccomp).
    code = ("import multiprocessing, socket\n"
            "a, b = socket.socketpair(); a.sendall(b'x'); print(b.recv(1).decode())\n"
            "socket.socket(socket.AF_INET).close()\n"
            "with multiprocessing.Pool(1) as pool: print(pool.apply(abs, (-3,)))\n")
    res = _py(_sandbox(tmp_path), code)
    assert res.returncode == 0, res.stderr
    assert res.stdout.split() == ["x", "3"]


@needs_unshare
def test_abstract_unix_sockets_are_unreachable_even_when_opted_in(tmp_path: Path):
    # Abstract sockets live in the network namespace, and the sandbox's is empty:
    # a listener on the host's abstract name cannot be reached from inside.
    name = f"\0openplow-isolation-{os.getpid()}"
    server = socket.socket(socket.AF_UNIX)
    server.bind(name)
    server.listen(1)
    try:
        code = ("import errno, socket\n"
                "s = socket.socket(socket.AF_UNIX)\n"
                "try:\n"
                f"    s.connect({name!r})\n"
                "    print('CONNECTED')\n"
                "except OSError as e:\n"
                "    print(errno.errorcode.get(e.errno, str(e.errno)))\n")
        res = _py(_sandbox(tmp_path, allow_unix_sockets=True), code)
    finally:
        server.close()
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip() == "ECONNREFUSED"


# ---- the protections hold together ---------------------------------------------

@needs_unshare
def test_a_hostile_poc_reaches_nothing_outside_its_scratch(tmp_path: Path, host_socket: Path):
    """One PoC that tries everything above in a row, as a real finding might."""
    outside = tmp_path / "outside.txt"
    code = (
        "import socket, subprocess\n"
        "tried = {}\n"
        "def attempt(name, fn):\n"
        "    try:\n"
        "        fn(); tried[name] = 'GOT THROUGH'\n"
        "    except OSError:\n"
        "        tried[name] = 'blocked'\n"
        f"attempt('write-outside', lambda: open({str(outside)!r}, 'w'))\n"
        "attempt('kernel', lambda: open('/proc/sys/kernel/core_pattern', 'w').write('|/x'))\n"
        "attempt('sysrq', lambda: open('/proc/sysrq-trigger', 'w'))\n"
        "attempt('kmsg', lambda: open('/dev/kmsg', 'w'))\n"
        f"attempt('unix', lambda: socket.socket(socket.AF_UNIX).connect({str(host_socket)!r}))\n"
        "attempt('net', lambda: socket.create_connection(('1.1.1.1', 53), 2))\n"
        "print(sorted(tried.items()))\n")
    res = _py(_sandbox(tmp_path), code)
    assert res.returncode == 0, res.stderr
    assert "GOT THROUGH" not in res.stdout, res.stdout
    assert not outside.exists()


def test_the_isolation_tests_skip_where_there_is_no_unshare():
    # Documents the platform contract: on macOS and Windows the sandbox is the stub,
    # and every test above skips rather than pretend. This one always runs.
    if sys.platform.startswith("linux") and _unshare_works():
        assert UnshareSandbox.available()
    else:
        assert subprocess.run([sys.executable, "-c", "pass"], check=False).returncode == 0
