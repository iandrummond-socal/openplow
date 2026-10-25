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
fails silently. A seccomp profile, a read-only bind of the target, and a
cgroup-v2 memory cap are the next hardening steps (see ``docs/ROADMAP.md``).
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

    def __init__(self, scratch: str | Path, *, timeout: int = 60,
                 limits: Limits | None = None):
        self.scratch = Path(scratch)
        self.scratch.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.limits = limits or Limits(cpu_seconds=timeout)

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
                env=self._clean_env(),
                capture_output=True,
                text=True,
                timeout=self.timeout,
                preexec_fn=_make_preexec(self.limits),
            )
            return SandboxResult(proc.returncode, proc.stdout, proc.stderr)
        except subprocess.TimeoutExpired as exc:
            return SandboxResult(124, exc.stdout or "", exc.stderr or "", timed_out=True)

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
    """Linux sandbox built on ``unshare``: a private user/net/pid/mount
    namespace (the net namespace is empty, so there is no external network),
    on top of the base rlimit caps."""

    backend = "unshare"

    @staticmethod
    def available() -> bool:
        return shutil.which("unshare") is not None

    def _wrap(self, argv: list[str]) -> list[str]:
        return [
            "unshare", "--user", "--map-root-user", "--net", "--pid", "--fork",
            "--mount-proc", "--",
            *argv,
        ]

    def run(self, argv: list[str], *, cwd: str | Path | None = None) -> SandboxResult:
        if not self.available():
            raise RuntimeError("unshare not found; install util-linux or use StubSandbox")
        return self._exec(self._wrap(argv), cwd)


def build_sandbox(kind: str, scratch: str | Path, **kwargs) -> Sandbox:
    if kind == "stub":
        return StubSandbox(scratch, **kwargs)
    if kind == "unshare":
        return UnshareSandbox(scratch, **kwargs)
    raise ValueError(f"unknown sandbox kind: {kind!r}")
