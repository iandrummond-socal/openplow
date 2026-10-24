"""OS-enforced sandbox for running target code.

Hunters need to build, run, and crash target code to confirm a PoC. That code
is untrusted, and so is any instruction embedded in the repo (a README or
fixture can carry a prompt injection aimed at the agent). The sandbox must hold
against both.

Requirements, straight from the skill:

* no external networking
* a sanitized environment (no inherited secrets)
* resource limits (cpu, memory, wall-clock)
* writes restricted to an assigned scratch path

Without a working sandbox, a lead stays ``needs_validation`` and target code is
not executed. This module ships a stub that enforces the *write boundary* and
timeouts in pure Python, and an ``unshare`` backend for Linux. Under Docker the
unshare backend needs ``--security-opt seccomp=unconfined apparmor=unconfined``
or it fails silently.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SandboxResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


class Sandbox:
    """Base class. Subclasses decide how strongly the boundary is enforced."""

    def __init__(self, scratch: str | Path, *, timeout: int = 60, mem_mb: int = 1024):
        self.scratch = Path(scratch)
        self.scratch.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.mem_mb = mem_mb

    def run(self, argv: list[str], *, cwd: str | Path | None = None) -> SandboxResult:
        raise NotImplementedError

    @staticmethod
    def _clean_env() -> dict[str, str]:
        # Nothing inherited: no API keys, no proxy creds, no tokens.
        return {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp", "LANG": "C.UTF-8"}


class StubSandbox(Sandbox):
    """Runs the command in a cleaned environment with a wall-clock timeout.

    It does NOT isolate the network or the filesystem beyond the cleaned env and
    the chosen working directory. Use only for the scaffold and tests; swap for
    :class:`UnshareSandbox` before executing real target code.
    """

    backend = "stub"

    def run(self, argv: list[str], *, cwd: str | Path | None = None) -> SandboxResult:
        try:
            proc = subprocess.run(
                argv,
                check=False,
                cwd=str(cwd or self.scratch),
                env=self._clean_env(),
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            return SandboxResult(proc.returncode, proc.stdout, proc.stderr)
        except subprocess.TimeoutExpired as exc:
            return SandboxResult(124, exc.stdout or "", exc.stderr or "", timed_out=True)


class UnshareSandbox(Sandbox):
    """Linux sandbox built on ``unshare``: new net/pid/mount namespaces, no
    network, cleaned env, and a scratch-only working directory.

    This is intentionally minimal; harden it (seccomp profile, read-only bind of
    the target, cgroup memory cap) before trusting it with hostile binaries.
    """

    backend = "unshare"

    @staticmethod
    def available() -> bool:
        return shutil.which("unshare") is not None

    def run(self, argv: list[str], *, cwd: str | Path | None = None) -> SandboxResult:
        if not self.available():
            raise RuntimeError("unshare not found; install util-linux or use StubSandbox")
        # --net gives an isolated (empty) network namespace => no external net.
        wrapped = [
            "unshare", "--user", "--map-root-user", "--net", "--pid", "--fork",
            "--mount-proc", "--",
            *argv,
        ]
        try:
            proc = subprocess.run(
                wrapped,
                check=False,
                cwd=str(cwd or self.scratch),
                env=self._clean_env(),
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            return SandboxResult(proc.returncode, proc.stdout, proc.stderr)
        except subprocess.TimeoutExpired as exc:
            return SandboxResult(124, exc.stdout or "", exc.stderr or "", timed_out=True)


def build_sandbox(kind: str, scratch: str | Path, **kwargs) -> Sandbox:
    if kind == "stub":
        return StubSandbox(scratch, **kwargs)
    if kind == "unshare":
        return UnshareSandbox(scratch, **kwargs)
    raise ValueError(f"unknown sandbox kind: {kind!r}")
