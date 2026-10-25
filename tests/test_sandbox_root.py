"""The minimal read-only root: a PoC cannot see the host beyond what it needs to run.

Each test runs a small hostile program inside a real ``unshare`` sandbox and asserts
that the host's files are not there. Where the protection can be switched off
(``minimal_root=False``) a twin shows the same program getting through, so a passing
test means the program was able to succeed without the protection.

The headline tests pass ``expose=()`` explicitly and run their payloads by name
(``python3``, ``sh``), so ``conftest.py`` cannot put a ``$HOME`` Python back in view.
They need Linux with unprivileged user namespaces; elsewhere they skip. Run them with
``scripts/test_linux.sh tests/test_sandbox_root.py``, and again with
``OPENPLOW_TEST_USER=1000``.
"""

from __future__ import annotations

import ast
import os
import shutil
import socket
import sys
from pathlib import Path

import pytest
from test_sandbox_hardening import _py, needs_unshare

from openplow import _sandbox_init as init
from openplow.sandbox import UnshareSandbox, build_sandbox

ALLOWED_TOP = {"usr", "bin", "sbin", "lib", "lib32", "lib64", "libx32",
               "etc", "dev", "proc", "tmp"}
HAS_PYTHON = any(os.path.exists(p) for p in ("/usr/bin/python3", "/usr/local/bin/python3"))
needs_python = pytest.mark.skipif(not HAS_PYTHON, reason="no python3 under /usr on this host")


def _sandbox(tmp_path: Path, **kwargs) -> UnshareSandbox:
    return UnshareSandbox(tmp_path / "scratch", timeout=20, **kwargs)


def _named(sb: UnshareSandbox, code: str, cwd=None):
    """Run python3 by name from the cleaned PATH (never by the test's own path)."""
    return sb.run(["python3", "-c", code], cwd=cwd)


def _secret(tmp_path: Path) -> Path:
    secret = tmp_path / "fakehome" / ".ssh" / "id_rsa"
    secret.parent.mkdir(parents=True)
    secret.write_text("PRIVATE KEY MATERIAL")
    return secret


def _scratch_top(tmp_path: Path) -> str:
    return (tmp_path / "scratch").resolve().parts[1]


def _arg_after(argv: list[str], flag: str) -> int:
    return argv.index(flag) + 1


@needs_unshare
@needs_python
def test_root_holds_only_the_allowlist(tmp_path: Path):
    res = _named(_sandbox(tmp_path, expose=()), "import os; print(sorted(os.listdir('/')))")
    assert res.returncode == 0, res.stderr
    seen = set(ast.literal_eval(res.stdout.strip()))
    assert seen <= ALLOWED_TOP | {_scratch_top(tmp_path)}, seen


_READ_SECRET = (
    "import os, sys\n"
    "try:\n"
    "    print('GOT', open(sys.argv[1]).read())\n"
    "except OSError as e:\n"
    "    print('BLOCKED', type(e).__name__)\n"
)


@needs_unshare
@needs_python
def test_home_and_secrets_are_unreadable(tmp_path: Path):
    secret = _secret(tmp_path)
    code = ("import os, sys\n"
            f"paths = [{str(secret)!r}, {str(secret.parent)!r}, {os.path.expanduser('~')!r}]\n"
            "paths += ['/root', '/home', '/mnt', '/media', '/opt', '/srv', '/var', '/run',\n"
            "          '/sys', '/boot']\n"
            "for p in paths:\n"
            "    try:\n"
            "        os.listdir(p) if os.path.isdir(p) else open(p).read()\n"
            "        print('VISIBLE', p)\n"
            "    except OSError as e:\n"
            "        print('hidden', type(e).__name__)\n")
    res = _named(_sandbox(tmp_path, expose=()), code)
    assert res.returncode == 0, res.stderr
    assert "VISIBLE" not in res.stdout, res.stdout
    assert "PRIVATE KEY" not in res.stdout


@needs_unshare
@needs_python
def test_invariant_sweep_finds_nothing_of_the_host(tmp_path: Path):
    secret = _secret(tmp_path)
    code = ("import os\n"
            "skip = ('/usr', '/lib', '/lib32', '/lib64', '/libx32', '/bin', '/sbin',\n"
            "        '/proc', '/dev')\n"
            "for root, dirs, files in os.walk('/', followlinks=False):\n"
            "    dirs[:] = [d for d in dirs if os.path.join(root, d) not in skip]\n"
            "    for n in dirs + files:\n"
            "        print(os.path.join(root, n))\n")
    res = _named(_sandbox(tmp_path, expose=()), code)
    assert res.returncode == 0, res.stderr
    assert "fakehome" not in res.stdout and secret.name not in res.stdout
    home = os.path.expanduser("~")
    assert home == "/" or home not in res.stdout
    for line in res.stdout.split():
        top = line.split("/")[1]
        assert top in ALLOWED_TOP | {_scratch_top(tmp_path)}, line
    assert not any(f"/etc/{name}" in res.stdout.split()
                   for name in ("shadow", "hostname", "resolv.conf"))


@needs_unshare
def test_minimal_root_twin_secret_is_readable_without_it(tmp_path: Path):
    secret = _secret(tmp_path)
    res = _py(_sandbox(tmp_path, minimal_root=False), f"print(open({str(secret)!r}).read())")
    assert "PRIVATE KEY MATERIAL" in res.stdout, res.stderr
    res = _py(_sandbox(tmp_path, expose=(tmp_path / "fakehome",)),
              f"print(open({str(secret)!r}).read())")
    assert "PRIVATE KEY MATERIAL" in res.stdout, res.stderr  # expose is the deliberate hole


@needs_unshare
@needs_python
def test_etc_is_synthesised(tmp_path: Path):
    code = ("import os, pwd, getpass\n"
            "print(sorted(l.split(':')[0] for l in open('/etc/passwd')))\n"
            "for n in ('shadow', 'ssh', 'hostname', 'resolv.conf'):\n"
            "    print(n, os.path.exists('/etc/' + n))\n"
            "print(pwd.getpwuid(0).pw_name, bool(getpass.getuser()))\n")
    res = _named(_sandbox(tmp_path, expose=()), code)
    assert res.returncode == 0, res.stderr
    lines = res.stdout.splitlines()
    assert lines[0] == "['nobody', 'root']"
    assert all(line.endswith("False") for line in lines[1:5]), lines
    assert lines[5].startswith("root")


@needs_unshare
def test_runtimes_still_run(tmp_path: Path):
    sb = _sandbox(tmp_path, expose=())
    res = sb.run(["sh", "-c", "echo hi; ls / >/dev/null; echo done"])
    assert res.returncode == 0 and res.stdout.split() == ["hi", "done"], res.stderr
    if HAS_PYTHON:
        res = _named(sb, "print(6 * 7)")
        assert res.stdout.strip() == "42", res.stderr
    for runtime in ("node", "ruby"):
        found = shutil.which(runtime)
        if found and os.path.realpath(found).startswith("/usr/"):
            assert sb.run([runtime, "--version"]).returncode == 0


@needs_unshare
def test_host_unix_sockets_are_not_visible_even_when_opted_in(tmp_path: Path):
    path = tmp_path / "host.sock"
    server = socket.socket(socket.AF_UNIX)
    server.bind(str(path))
    server.listen(1)
    code = ("import socket, errno\n"
            "s = socket.socket(socket.AF_UNIX)\n"
            "try:\n"
            f"    s.connect({str(path)!r})\n"
            "    print('CONNECTED')\n"
            "except OSError as e:\n"
            "    print(errno.errorcode.get(e.errno))\n")
    try:
        res = _py(_sandbox(tmp_path, allow_unix_sockets=True), code)
        assert res.stdout.strip() == "ENOENT", (res.stdout, res.stderr)
        twin = _py(_sandbox(tmp_path, allow_unix_sockets=True, minimal_root=False), code)
        assert twin.stdout.strip() == "CONNECTED", (twin.stdout, twin.stderr)
    finally:
        server.close()
    markers = []
    for d in ("/run", "/var/run"):
        if os.access(d, os.W_OK):
            m = Path(d) / f"openplow-root-test-{os.getpid()}"
            m.write_text("x")
            markers.append(m)
    try:
        for m in markers:
            r = _py(_sandbox(tmp_path), f"import os; print(os.path.exists({str(m)!r}))")
            assert r.stdout.strip() == "False", m
    finally:
        for m in markers:
            m.unlink(missing_ok=True)


@needs_unshare
@pytest.mark.parametrize("inside_scratch", [True, False])
def test_target_and_scratch_semantics_are_unchanged(tmp_path: Path, inside_scratch: bool):
    base = tmp_path / "scratch" if inside_scratch else tmp_path / "elsewhere"
    target = base / "target"
    target.mkdir(parents=True)
    (target / "f.txt").write_text("target data")
    sb = _sandbox(tmp_path)
    code = ("import errno\n"
            "print(open('f.txt').read())\n"
            "try:\n"
            "    open('new.txt', 'w').write('x')\n"
            "    print('WROTE')\n"
            "except OSError as e:\n"
            "    print(errno.errorcode[e.errno])\n"
            "open('/etc/zz', 'w') if False else None\n")
    res = _py(sb, code, cwd=target)
    assert res.stdout.split() == ["target", "data", "EROFS"], (res.stdout, res.stderr)
    scratch_write = _py(sb, f"open({str(tmp_path / 'scratch' / 'ok.txt')!r}, 'w').write('x')")
    assert scratch_write.returncode == 0, scratch_write.stderr
    other = _py(sb, "open('/etc/openplow-test', 'w')")
    assert "Read-only file system" in other.stderr


@needs_unshare
def test_expose_makes_a_path_visible_read_only(tmp_path: Path):
    extra = tmp_path / "extra"
    extra.mkdir()
    (extra / "tool.txt").write_text("exposed")
    _secret(tmp_path)
    code = ("import os\n"
            f"print(open({str(extra / 'tool.txt')!r}).read())\n"
            "try:\n"
            f"    open({str(extra / 'new')!r}, 'w')\n"
            "    print('WROTE')\n"
            "except OSError as e:\n"
            "    print('EROFS' if e.errno == 30 else e.errno)\n"
            f"print(os.path.exists({str(tmp_path / 'fakehome')!r}))\n")
    res = _py(_sandbox(tmp_path, expose=(extra,)), code)
    assert res.stdout.split() == ["exposed", "EROFS", "False"], (res.stdout, res.stderr)


def _argv_with(tmp_path: Path, mutate) -> UnshareSandbox:
    class Broken(UnshareSandbox):
        def _wrap(self, argv, cwd=None, status_fd=None):
            out = super()._wrap(argv, cwd, status_fd)
            mutate(out)
            return out
    return Broken(tmp_path / "scratch", timeout=20, expose=())


def _adding(tmp_path: Path, flag: str, value: str) -> UnshareSandbox:
    """A sandbox whose launcher argv also carries ``flag value`` (after scratch)."""
    def mutate(out):
        at = _arg_after(out, "--rw") + 1
        out[at:at] = [flag, value]
    return _argv_with(tmp_path, mutate)


def _assert_refused(res) -> None:
    assert res.returncode == 125 and "openplow sandbox" in res.stderr, (res.stdout, res.stderr)
    assert "ran" not in res.stdout
    assert res.enforced and not any(res.enforced.values())


@needs_unshare
@pytest.mark.parametrize("bad", ["/", "/proc", "relative/path", "/does/not/exist/at/all"])
def test_expose_refuses_dangerous_paths(tmp_path: Path, bad: str):
    _assert_refused(_py(_adding(tmp_path, "--expose", bad), "print('ran')"))


@needs_unshare
@pytest.mark.parametrize("flag", ["--ro", "--expose"])
@pytest.mark.parametrize("bad", ["/", "/proc", "relative", "MISSING", "PARENT"])
def test_bad_paths_fail_closed_before_anything_is_written(tmp_path: Path, flag: str, bad: str):
    value = {"MISSING": str(tmp_path / "nope"), "PARENT": str(tmp_path)}.get(bad, bad)

    _assert_refused(_py(_adding(tmp_path, flag, value), "print('ran')"))
    assert not list((tmp_path / "scratch").glob(".openplow-stage-*"))


@needs_unshare
def test_scratch_under_a_system_directory_is_refused_and_writes_nothing(tmp_path: Path):
    def mutate(out):
        out[_arg_after(out, "--rw")] = "/usr/lib"
    _assert_refused(_py(_argv_with(tmp_path, mutate), "print('ran')"))
    stray = list(Path("/usr/lib").glob(".openplow-stage-*"))
    for s in stray:
        s.rmdir()
    assert not stray


@needs_unshare
def test_minimal_root_needs_minimal_dev(tmp_path: Path):
    with pytest.raises(ValueError):
        _sandbox(tmp_path, minimal_dev=False)
    res = _py(_sandbox(tmp_path, minimal_root=False, minimal_dev=False), "print('ran')")
    assert res.returncode == 0 and "ran" in res.stdout, res.stderr

    _assert_refused(_py(_adding(tmp_path, "--no-minimal-dev", "--no-proc-harden"),
                        "print('ran')"))


@needs_unshare
def test_everything_in_the_new_root_is_read_only_even_with_readonly_fs_off(tmp_path: Path):
    extra = tmp_path / "extra"
    extra.mkdir()
    code = ("import errno, os\n"
            "def w(p):\n"
            "    try:\n"
            "        open(p, 'w')\n"
            "        return 'WRITABLE'\n"
            "    except OSError as e:\n"
            "        return errno.errorcode[e.errno]\n"
            "alt = ['/etc/alternatives/zz'] if os.path.isdir('/etc/alternatives') else []\n"
            f"paths = ['/etc/ld.so.cache', '/zz', '/etc/zz', {str(extra / 'zz')!r}] + alt\n"
            "for p in paths:\n"
            "    print(p, w(p))\n"
            f"print(w({str(tmp_path / 'scratch' / 'ok')!r}))\n")
    res = _py(_sandbox(tmp_path, readonly_fs=False, expose=(extra,)), code)
    lines = res.stdout.splitlines()
    assert lines and lines[-1] == "WRITABLE", (res.stdout, res.stderr)
    assert all(line.endswith("EROFS") for line in lines[:-1]), lines


@needs_unshare
def test_launcher_holds_nothing_from_the_old_root(tmp_path: Path):
    code = ("import os, glob\n"
            "paths = glob.glob('/proc/self/fd/*') + ['/proc/self/cwd', '/proc/self/root',\n"
            "                                      '/proc/1/root']\n"
            "for p in paths:\n"
            "    try:\n"
            "        t = os.readlink(p)\n"
            "    except OSError:\n"
            "        continue\n"
            "    ok = t.startswith(('pipe:', 'socket:', 'anon_inode:')) or os.path.exists(t)\n"
            "    print('OK' if ok else 'LEAK ' + t)\n")
    res = _py(_sandbox(tmp_path), code)
    assert res.returncode == 0, res.stderr
    assert "LEAK" not in res.stdout, res.stdout


@needs_unshare
def test_cold_start_and_repeat_runs_leave_no_stage_behind(tmp_path: Path):
    sb = _sandbox(tmp_path)
    stage = tmp_path / "scratch"
    for _ in range(2):
        assert _py(sb, "print('ran')").returncode == 0
        assert not list(stage.glob(".openplow-stage-*"))
    sb2 = _adding(tmp_path, "--ro", str(tmp_path / "nope"))
    _assert_refused(_py(sb2, "print('ran')"))
    assert not list(stage.glob(".openplow-stage-*"))


@needs_unshare
def test_enforced_reports_minimal_root(tmp_path: Path):
    assert _py(_sandbox(tmp_path), "pass").enforced["minimal_root"] is True
    off = _py(_sandbox(tmp_path, minimal_root=False), "pass")
    assert off.enforced["minimal_root"] is False

    def mutate(out):
        out[_arg_after(out, "--rw")] = str(tmp_path / "does-not-exist")
    res = _py(_argv_with(tmp_path, mutate), "pass")
    assert res.returncode == 125 and not any(res.enforced.values())


def test_contract_drift():
    path = UnshareSandbox(Path("/tmp/openplow-drift-check"), timeout=1)._clean_env()["PATH"]
    for entry in path.split(":"):
        assert entry.split("/")[1] in init._ROOT_DIRS, entry
    assert init._ARCHES["x86_64"][1]["pivot_root"] == 155
    assert init._ARCHES["aarch64"][1]["pivot_root"] == 41


@needs_unshare
@needs_python
def test_nothing_is_imported_after_the_switch(tmp_path: Path):
    tree = ast.parse(Path(init.__file__).read_text())
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for node in ast.walk(fn):
                assert not isinstance(node, (ast.Import, ast.ImportFrom)), fn.name
    prefix = Path(sys.base_prefix)
    copy = tmp_path / "py"
    try:
        shutil.copytree(prefix, copy, symlinks=True, ignore=shutil.ignore_patterns(
            "test", "tests", "idlelib", "__pycache__", "site-packages"))
        python = copy / "bin" / "python3"
        assert python.exists()
    except (OSError, shutil.Error):
        pytest.skip("this interpreter cannot be relocated")

    class Relocated(UnshareSandbox):
        def _wrap(self, argv, cwd=None, status_fd=None):
            out = super()._wrap(argv, cwd, status_fd)
            out[out.index("-I") - 1] = str(python)  # the launcher's interpreter
            return out

    res = Relocated(tmp_path / "scratch", timeout=20, expose=()).run(["sh", "-c", "echo ok"])
    if res.returncode != 0 and "cannot execute" in res.stderr:
        pytest.skip("relocated interpreter will not start on this host")
    assert res.returncode == 0 and res.stdout.strip() == "ok", (res.stdout, res.stderr)


@needs_unshare
def test_setup_failure_fails_closed(tmp_path: Path):
    # The pivot itself cannot be made to fail on demand without a fault hook, so its own
    # error path is covered by review; this proves a failed setup runs no payload.
    def mutate(out):
        out[_arg_after(out, "--rw")] = str(tmp_path / "does-not-exist")
    _assert_refused(_py(_argv_with(tmp_path, mutate), "print('ran')"))


@needs_unshare
def test_build_sandbox_reads_the_expose_variable(tmp_path: Path, monkeypatch):
    extra = tmp_path / "extra"
    extra.mkdir()
    (extra / "x.txt").write_text("seen")
    code = f"print(open({str(extra / 'x.txt')!r}).read())"
    monkeypatch.setenv("OPENPLOW_SANDBOX_EXPOSE", str(extra))
    sb = build_sandbox("unshare", tmp_path / "scratch", timeout=20)
    assert _py(sb, code).stdout.strip() == "seen"
    monkeypatch.delenv("OPENPLOW_SANDBOX_EXPOSE")
    sb = build_sandbox("unshare", tmp_path / "scratch2", timeout=20)
    assert "seen" not in _py(sb, code).stdout
