"""OS-enforced sandbox for running target code and proofs of concept.

Hunters need to build, run, and crash target code to confirm a PoC. That code
is untrusted, and so is any instruction embedded in the repo (a README or
fixture can carry a prompt injection aimed at the agent). The sandbox must hold
against both.

Requirements, straight from the skill:

* no external networking
* a sanitized environment (no inherited secrets)
* resource limits (cpu, memory, wall-clock, file size, processes)
* writes restricted to an assigned scratch path

Two backends:

* :class:`StubSandbox` — cleaned env, wall-clock timeout, and POSIX ``rlimit``
  caps (cpu, file size, processes, optional address space). No network or
  filesystem namespace isolation; use for the scaffold, tests, and trusted code.
* :class:`UnshareSandbox` — adds Linux namespaces via ``unshare`` (an empty
  network namespace => no external net, a private pid/mount namespace), on top
  of the same rlimit caps.

Under Docker the unshare backend needs
``--security-opt seccomp=unconfined --security-opt apparmor=unconfined`` or it
fails silently. The unshare backend also makes the filesystem read-only (except
scratch), drops all capabilities and loads a seccomp denylist; see
:mod:`openplow._sandbox_init`. ``Limits.memory_mb`` caps the data segment
everywhere and, where a cgroup-v2 subtree with the memory controller is
delegated to this process, also sets a hard cgroup cap (see :func:`_cgroup_parent`).
"""

from __future__ import annotations

import itertools
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

try:  # POSIX only
    import resource
except ImportError:  # pragma: no cover - non-POSIX
    resource = None  # type: ignore[assignment]


@dataclass
class SandboxResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    # True when the cgroup memory cap killed the run (``memory.events`` oom_kill).
    oom_killed: bool = False
    # Which protections were actually active for this run, e.g. ``seccomp: True``.
    # Empty means "none claimed": the stub backend enforces nothing beyond env,
    # timeout and rlimits. Never assume a protection that is not listed here.
    enforced: dict[str, bool] = field(default_factory=dict)


@dataclass
class Limits:
    """Resource caps applied to every sandboxed process."""
    cpu_seconds: int = 30
    file_size_mb: int = 256
    max_procs: int = 64
    # Address-space cap. 0 disables it: RLIMIT_AS set too low breaks many
    # interpreters, so memory is better capped with a cgroup. Opt in explicitly.
    address_space_mb: int = 0
    # Data-segment cap (RLIMIT_DATA): limits heap and private anonymous memory.
    # Unlike RLIMIT_AS it ignores reserved-but-unused address space, so
    # interpreters such as Node still start. 0 disables it. It does not count
    # shared memory, so where a cgroup is delegated the same number is also set
    # as a hard cgroup cap (memory.max, no swap).
    memory_mb: int = 0


_CGROUP_ROOT = Path("/sys/fs/cgroup")
_leaf_ids = itertools.count()
_warned_no_cgroup = False


def _cgroup_parent(root: Path = _CGROUP_ROOT, proc_cgroup: Path = Path("/proc/self/cgroup")
                   ) -> Path | None:
    """A cgroup directory this process may create a memory-capped leaf under, or None.

    OpenPlow never moves other processes or edits a parent's ``subtree_control``:
    it only uses a place where the memory controller is already delegated and
    writable. That is this process's own cgroup, or its parent (a sibling leaf),
    which is how a systemd-delegated scope or a harness that did the delegation
    looks. On a plain desktop session neither holds and there is no cgroup cap.
    """
    try:
        if not (root / "cgroup.controllers").exists():  # not cgroup v2
            return None
        rel = next(line.split(":", 2)[2].strip()
                   for line in proc_cgroup.read_text().splitlines() if line.startswith("0::"))
    except (OSError, StopIteration, IndexError):
        return None
    own = root / rel.lstrip("/")
    for candidate in (own, own.parent) if own != root else (own,):
        try:
            delegated = "memory" in (candidate / "cgroup.subtree_control").read_text().split()
        except OSError:
            continue
        if delegated and os.access(candidate, os.W_OK):
            return candidate
    return None


def _make_cgroup_leaf(limits: Limits, parent: Path | None = None) -> Path | None:
    """Create a memory-capped leaf cgroup, or None (with one warning) if it cannot."""
    global _warned_no_cgroup
    parent = parent or _cgroup_parent()
    leaf = None
    try:
        if parent is None:
            raise OSError("no delegated cgroup with the memory controller")
        leaf = parent / f"openplow-{os.getpid()}-{next(_leaf_ids)}"
        leaf.mkdir()
        (leaf / "memory.max").write_text(str(limits.memory_mb * 1024 * 1024))
        try:
            (leaf / "memory.swap.max").write_text("0")
        except OSError:
            pass  # swap accounting may be off; memory.max still holds
        return leaf
    except OSError as exc:
        if leaf is not None:
            _remove_cgroup_leaf(leaf)
        if not _warned_no_cgroup:
            _warned_no_cgroup = True
            sys.stderr.write(f"openplow sandbox: no memory cap from a cgroup ({exc}); "
                             "only the data-segment limit applies\n")
        return None


def _read_oom_kills(leaf: Path) -> bool:
    try:
        for line in (leaf / "memory.events").read_text().splitlines():
            if line.startswith("oom_kill "):
                return int(line.split()[1]) > 0
    except (OSError, ValueError, IndexError):
        pass
    return False


def _remove_cgroup_leaf(leaf: Path) -> None:
    """Kill anything left in the leaf, then remove it (a cgroup with live
    processes cannot be removed)."""
    try:
        (leaf / "cgroup.kill").write_text("1")
    except OSError:
        pass
    for _ in range(50):
        try:
            leaf.rmdir()
            return
        except FileNotFoundError:
            return
        except OSError:
            time.sleep(0.02)


def _nproc_capped(platform: str | None = None) -> bool:
    """Whether RLIMIT_NPROC is applied. macOS counts every process the user owns
    against it, not just the sandbox's, so a cap of 64 stops any child from
    forking (even a PoC's shell) on a normal desktop session. It stays on
    elsewhere, where it is scoped by the namespace or the container."""
    return (platform or sys.platform) != "darwin"


def _make_preexec(limits: Limits, cgroup_procs: Path | None = None):
    """Build a preexec_fn that puts the child in its own session and applies
    rlimits before exec. Returns None where rlimits are unavailable.

    With ``cgroup_procs`` the child first joins that cgroup, so the memory cap
    covers it from its first instruction."""
    if resource is None:
        return None

    def _preexec() -> None:  # pragma: no cover - runs in the child process
        os.setsid()  # detach from the parent's controlling terminal / group
        if cgroup_procs is not None:
            with open(cgroup_procs, "w") as procs:
                procs.write(str(os.getpid()))
        _set(resource.RLIMIT_CPU, limits.cpu_seconds)
        _set(resource.RLIMIT_FSIZE, limits.file_size_mb * 1024 * 1024)
        if _nproc_capped():
            _set(resource.RLIMIT_NPROC, limits.max_procs)
        _set(resource.RLIMIT_CORE, 0)  # no core dumps
        if limits.memory_mb > 0:
            _set(resource.RLIMIT_DATA, limits.memory_mb * 1024 * 1024)
        if limits.address_space_mb > 0:
            _set(resource.RLIMIT_AS, limits.address_space_mb * 1024 * 1024)

    def _set(what: int, value: int) -> None:
        try:
            _soft, hard = resource.getrlimit(what)
            cap = value if hard == resource.RLIM_INFINITY else min(value, hard)
            resource.setrlimit(what, (cap, cap))
        except (ValueError, OSError):
            pass

    return _preexec


class Sandbox:
    """Base class. Subclasses decide how strongly the boundary is enforced."""

    backend = "base"
    # Memory cap used when the caller passes no Limits. Off for the stub, which
    # runs trusted code; the unshare backend sets its own.
    default_memory_mb = 0

    def __init__(self, scratch: str | Path, *, timeout: int = 60,
                 limits: Limits | None = None):
        self.scratch = Path(scratch)
        self.scratch.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.limits = limits or Limits(cpu_seconds=timeout,
                                       memory_mb=self.default_memory_mb)

    def run(self, argv: list[str], *, cwd: str | Path | None = None) -> SandboxResult:
        raise NotImplementedError

    def _wrap(self, argv: list[str]) -> list[str]:
        return argv

    def _exec(self, argv: list[str], cwd: str | Path | None, *,
              pass_fds: tuple[int, ...] = (), cgroup: Path | None = None) -> SandboxResult:
        try:
            proc = subprocess.run(
                argv,
                check=False,
                cwd=str(cwd or self.scratch),
                env=self._env(),
                capture_output=True,
                text=True,
                timeout=self.timeout,
                preexec_fn=_make_preexec(self.limits, cgroup / "cgroup.procs" if cgroup else None),
                pass_fds=pass_fds,
            )
            return SandboxResult(proc.returncode, proc.stdout, proc.stderr)
        except subprocess.TimeoutExpired as exc:
            return SandboxResult(124, exc.stdout or "", exc.stderr or "", timed_out=True)

    def _env(self) -> dict[str, str]:
        return self._clean_env()

    @staticmethod
    def _clean_env() -> dict[str, str]:
        # Nothing inherited: no API keys, no proxy creds, no tokens.
        return {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp", "LANG": "C.UTF-8"}


class StubSandbox(Sandbox):
    """Cleaned env + wall-clock timeout + rlimit caps. No namespace isolation."""

    backend = "stub"

    def run(self, argv: list[str], *, cwd: str | Path | None = None) -> SandboxResult:
        return self._exec(argv, cwd)


class UnshareSandbox(Sandbox):
    """Linux sandbox built on ``unshare``.

    * a private user/net/pid/mount namespace; the net namespace is empty, so
      there is no external network;
    * the whole filesystem is read-only, except the scratch directory, and the
      working directory the caller passes is read-only even inside scratch
      (``readonly_fs``);
    * ``/dev`` is a fresh, minimal tree (``null zero full random urandom tty``,
      a private ``pts`` and ``shm``), so host devices such as ``kmsg``, ``mem``
      and loop devices are not reachable (``minimal_dev``);
    * the kernel-tunable parts of ``/proc`` (``sys``, ``sysrq-trigger``, ``bus``,
      ``fs``, ``irq``) are read-only and the leaky files (``kcore``, ``keys``,
      ``timer_list`` ...) are masked, while ``/proc/self`` stays writable
      (``proc_hardened``);
    * every capability is dropped, and a seccomp denylist blocks mount, ptrace,
      bpf, module loading, namespace creation and io_uring (``seccomp``);
    * creating a unix socket (``socket(AF_UNIX, ...)``) fails with EPERM, so the
      payload cannot reach host daemons (ssh-agent, DBus, ``docker.sock``,
      gpg-agent) wherever their sockets sit (``unix_sockets_blocked``).
      ``socketpair`` still works, so multiprocessing, asyncio and subprocess are
      unaffected. This default BREAKS a PoC that runs or talks to its own
      unix-socket server; such a PoC needs ``allow_unix_sockets=True``;
    * the base rlimit caps, including a 2 GiB data-segment cap by default.

    The filesystem, ``/dev``, ``/proc``, capability and seccomp steps run in
    :mod:`openplow._sandbox_init`, after the namespaces exist; each can be turned
    off with its keyword (``minimal_dev=False``, ``harden_proc=False`` ...). If a
    step that is on cannot be applied, the command does not run (exit 125).
    ``HOME`` and ``TMPDIR`` point at the scratch directory, because ``/tmp`` is
    read-only inside the sandbox.
    """

    backend = "unshare"
    default_memory_mb = 2048

    def __init__(self, scratch: str | Path, *, readonly_fs: bool = True,
                 seccomp: bool = True, minimal_dev: bool = True,
                 harden_proc: bool = True, allow_unix_sockets: bool = False, **kwargs):
        super().__init__(scratch, **kwargs)
        self.readonly_fs = readonly_fs
        self.seccomp = seccomp
        self.minimal_dev = minimal_dev
        self.harden_proc = harden_proc
        self.allow_unix_sockets = allow_unix_sockets

    @staticmethod
    def available() -> bool:
        return shutil.which("unshare") is not None

    def _env(self) -> dict[str, str]:
        env = self._clean_env()
        env["HOME"] = env["TMPDIR"] = str(self.scratch.resolve())
        return env

    def _wrap(self, argv: list[str], cwd: str | Path | None = None,
              status_fd: int | None = None) -> list[str]:
        init = [sys.executable, "-I", str(Path(__file__).with_name("_sandbox_init.py"))]
        if self.readonly_fs or self.minimal_dev:
            # Scratch is always the FIRST --rw: the launcher makes its staging
            # directories under the first --rw path, so a hide step needs it even
            # when the filesystem is left writable (without it the launcher exits 125).
            init += ["--rw", str(self.scratch.resolve())]
        if self.readonly_fs:
            if cwd is not None:
                # The working directory is the target under test: readable, never
                # writable, wherever it sits (usually inside scratch).
                init += ["--ro", str(Path(cwd).resolve())]
        else:
            init += ["--no-readonly"]
        if not self.seccomp:
            init += ["--no-seccomp"]
        if not self.minimal_dev:
            init += ["--no-minimal-dev"]
        if not self.harden_proc:
            init += ["--no-proc-harden"]
        if self.allow_unix_sockets:
            init += ["--allow-unix-sockets"]
        if status_fd is not None:
            init += ["--status-fd", str(status_fd)]
        # --kill-child: a timeout kills `unshare`, and without this the payload
        # and its children would keep running as orphans in the pid namespace.
        return [
            "unshare", "--user", "--map-root-user", "--net", "--pid", "--fork",
            "--kill-child", "--mount-proc", "--",
            *init, "--", *argv,
        ]

    def run(self, argv: list[str], *, cwd: str | Path | None = None) -> SandboxResult:
        if not self.available():
            raise RuntimeError("unshare not found; install util-linux or use StubSandbox")
        leaf = _make_cgroup_leaf(self.limits) if self.limits.memory_mb > 0 else None
        read_fd, write_fd = os.pipe()
        try:
            result = self._exec(self._wrap(argv, cwd, write_fd), cwd,
                                pass_fds=(write_fd,), cgroup=leaf)
        finally:
            os.close(write_fd)  # the parent's copy, so the read below sees EOF
            if leaf is not None:
                oom = _read_oom_kills(leaf)
                _remove_cgroup_leaf(leaf)
        with os.fdopen(read_fd, "rb") as status:
            reported = status.read().decode(errors="replace")
        result.enforced = self._enforced(reported, result, capped=leaf is not None)
        result.oom_killed = leaf is not None and oom
        return result

    def _enforced(self, reported: str, result: SandboxResult, *,
                  capped: bool = False) -> dict[str, bool]:
        """Turn the launcher's status report into ``SandboxResult.enforced``.

        Only the launcher writes the report, just before ``exec``, so a payload
        cannot claim protections it lacks. No report, or exit 125 (the launcher's
        failure code), means nothing is claimed: a payload that exits 125 itself
        only makes the report more cautious, never less.
        """
        applied = set(reported.split(",")) - {""}
        if result.returncode == 125:
            applied = set()
        reached = bool(applied)
        return {
            "network_isolated": reached,
            "readonly_fs": "readonly_fs" in applied,
            "no_capabilities": "no_capabilities" in applied,
            "seccomp": "seccomp" in applied,
            "minimal_dev": "minimal_dev" in applied,
            "proc_hardened": "proc_hardened" in applied,
            "unix_sockets_blocked": "unix_sockets_blocked" in applied,
            # heap_limit is the RLIMIT_DATA fallback; memory_cap is the hard cgroup cap
            # and is False wherever no cgroup was delegated.
            "heap_limit": reached and self.limits.memory_mb > 0,
            "memory_cap": reached and capped,
        }


def build_sandbox(kind: str, scratch: str | Path, **kwargs) -> Sandbox:
    if kind == "stub":
        return StubSandbox(scratch, **kwargs)
    if kind == "unshare":
        return UnshareSandbox(scratch, **kwargs)
    raise ValueError(f"unknown sandbox kind: {kind!r}")
