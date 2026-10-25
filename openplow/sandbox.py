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
:mod:`openplow._sandbox_init`. A cgroup-v2 memory cap is the remaining step (see
``docs/ROADMAP.md``); until then ``Limits.memory_mb`` caps the data segment.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
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
    # interpreters such as Node still start. 0 disables it. This is the memory
    # cap until a cgroup-v2 cap is added (cgroups need a delegated subtree).
    memory_mb: int = 0


def _nproc_capped(platform: str | None = None) -> bool:
    """Whether RLIMIT_NPROC is applied. macOS counts every process the user owns
    against it, not just the sandbox's, so a cap of 64 stops any child from
    forking (even a PoC's shell) on a normal desktop session. It stays on
    elsewhere, where it is scoped by the namespace or the container."""
    return (platform or sys.platform) != "darwin"


def _make_preexec(limits: Limits):
    """Build a preexec_fn that puts the child in its own session and applies
    rlimits before exec. Returns None where rlimits are unavailable."""
    if resource is None:
        return None

    def _preexec() -> None:  # pragma: no cover - runs in the child process
        os.setsid()  # detach from the parent's controlling terminal / group
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

    def _exec(self, argv: list[str], cwd: str | Path | None) -> SandboxResult:
        try:
            proc = subprocess.run(
                argv,
                check=False,
                cwd=str(cwd or self.scratch),
                env=self._env(),
                capture_output=True,
                text=True,
                timeout=self.timeout,
                preexec_fn=_make_preexec(self.limits),
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
    * every capability is dropped, and a seccomp denylist blocks mount, ptrace,
      bpf, module loading, namespace creation and io_uring (``seccomp``);
    * the base rlimit caps, including a 2 GiB data-segment cap by default.

    The last three steps run in :mod:`openplow._sandbox_init`, after the
    namespaces exist. If a step cannot be applied, the command does not run.
    ``HOME`` and ``TMPDIR`` point at the scratch directory, because ``/tmp`` is
    read-only inside the sandbox.
    """

    backend = "unshare"
    default_memory_mb = 2048

    def __init__(self, scratch: str | Path, *, readonly_fs: bool = True,
                 seccomp: bool = True, **kwargs):
        super().__init__(scratch, **kwargs)
        self.readonly_fs = readonly_fs
        self.seccomp = seccomp

    @staticmethod
    def available() -> bool:
        return shutil.which("unshare") is not None

    def _env(self) -> dict[str, str]:
        env = self._clean_env()
        env["HOME"] = env["TMPDIR"] = str(self.scratch.resolve())
        return env

    def _wrap(self, argv: list[str], cwd: str | Path | None = None) -> list[str]:
        init = [sys.executable, "-I", str(Path(__file__).with_name("_sandbox_init.py"))]
        if self.readonly_fs:
            init += ["--rw", str(self.scratch.resolve())]
            if cwd is not None:
                # The working directory is the target under test: readable, never
                # writable, wherever it sits (usually inside scratch).
                init += ["--ro", str(Path(cwd).resolve())]
        else:
            init += ["--no-readonly"]
        if not self.seccomp:
            init += ["--no-seccomp"]
        return [
            "unshare", "--user", "--map-root-user", "--net", "--pid", "--fork",
            "--mount-proc", "--",
            *init, "--", *argv,
        ]

    def run(self, argv: list[str], *, cwd: str | Path | None = None) -> SandboxResult:
        if not self.available():
            raise RuntimeError("unshare not found; install util-linux or use StubSandbox")
        return self._exec(self._wrap(argv, cwd), cwd)


def build_sandbox(kind: str, scratch: str | Path, **kwargs) -> Sandbox:
    if kind == "stub":
        return StubSandbox(scratch, **kwargs)
    if kind == "unshare":
        return UnshareSandbox(scratch, **kwargs)
    raise ValueError(f"unknown sandbox kind: {kind!r}")
