"""Running a finding's proof of concept, and the fail->pass patch gate.

Two jobs:

* :func:`run_poc` — the false-positive control. The PoC runs in the sandbox
  against a pristine copy of the target and must demonstrate the issue (exit 0,
  and any declared ``observed`` marker appears). Source is hashed before and
  after; a PoC that edits pre-existing source is rejected as tampered.
* :func:`run_patch_gate` — closes the loop on a confirmed finding. The PoC must
  reproduce against the untouched code, the finding's patch is applied, and the
  PoC must then *stop* reproducing. Only a clean fail->pass flip passes the gate.

Only PoCs of kind ``test`` or ``script`` are executed. ``input`` and ``trace``
PoCs are not auto-run (no generic harness).
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .sandbox import Sandbox

# Interpreter per PoC file suffix. No network tools; just local runtimes.
_RUNNERS = {
    ".py": ["python3"],
    ".js": ["node"],
    ".sh": ["sh"],
    ".rb": ["ruby"],
}

_IGNORE = shutil.ignore_patterns(".git", "node_modules", "__pycache__", ".venv",
                                 "venv", "dist", "build", "target")


@dataclass
class PocRun:
    attempted: bool
    demonstrated: bool = False
    integrity_ok: bool = True
    returncode: int | None = None
    output: str = ""
    reason: str = ""
    # The sandbox's wall-clock limit killed the PoC, so feedback can classify a
    # timeout from a flag rather than by parsing ``reason``.
    timed_out: bool = False
    # Which sandbox protections were active for this run (``SandboxResult.enforced``).
    enforced: dict[str, bool] = field(default_factory=dict)


@dataclass
class PatchGate:
    attempted: bool
    reproduced_before: bool = False
    patch_applied: bool = False
    reproduced_after: bool = False
    passed: bool = False
    reason: str = ""


def _snapshot(root: Path, exclude: set[Path]) -> dict[str, str]:
    """Hash of every pre-existing source file under root, keyed by relative path."""
    snap: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path in exclude:
            continue
        rel = path.relative_to(root)
        if any(part in {".git", "node_modules", "__pycache__"} for part in rel.parts):
            continue
        snap[str(rel)] = hashlib.sha256(path.read_bytes()).hexdigest()
    return snap


def tree_digest(root: Path) -> str:
    """One hash for the source tree under ``root`` (same files ``_snapshot`` sees).

    A benchmark run records it for each target, so a later re-run of the fix gate
    can tell whether the target it would run against is the one the run used."""
    h = hashlib.sha256()
    for rel, digest in _snapshot(root, exclude=set()).items():
        h.update(f"{rel}\0{digest}\n".encode())
    return h.hexdigest()


def _tampered(root: Path, before: dict[str, str], exclude: set[Path]) -> bool:
    """True if any file present before the run was modified or removed. Files the
    exploit newly *creates* are not tampering — only edits to existing source are."""
    for rel, digest in before.items():
        path = root / rel
        if path in exclude:
            continue
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            return True
    return False


def _poc_filename(poc: dict[str, Any]) -> str:
    if poc.get("path"):
        return Path(poc["path"]).name
    ext = {"test": ".py", "script": ".py"}.get(poc.get("kind", ""), ".txt")
    return f"openplow_poc{ext}"


def _executable_poc(finding: dict[str, Any]) -> dict[str, Any] | None:
    poc = finding.get("poc") or {}
    if poc.get("kind") not in ("test", "script"):
        return None
    if not poc.get("content") and not poc.get("path"):
        return None
    return poc


def _prepare_target(repo: Path, workdir: Path, poc: dict[str, Any]) -> tuple[Path, Path]:
    """Copy the repo to a fresh scratch dir and write the PoC file into it."""
    target = workdir / "target"
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(repo, target, ignore=_IGNORE)
    poc_path = target / _poc_filename(poc)
    if poc.get("content"):
        poc_path.write_text(poc["content"], encoding="utf-8")
    return target, poc_path


def _demonstrates(sandbox: Sandbox, target: Path, poc_path: Path,
                  poc: dict[str, Any]) -> tuple[bool, str, int | None, bool, dict[str, bool]]:
    """Run the PoC once. Returns (demonstrated, output, returncode, timed_out, enforced)."""
    runner = _RUNNERS.get(poc_path.suffix)
    if runner is None or shutil.which(runner[0]) is None:
        return False, f"no runtime for {poc_path.suffix}", None, False, {}
    result = sandbox.run([*runner, poc_path.name], cwd=target)
    output = (result.stdout + result.stderr)[-4000:]
    observed = poc.get("observed")
    demonstrated = result.returncode == 0 and (observed is None or observed in output)
    return demonstrated, output, result.returncode, result.timed_out, result.enforced


def run_poc(sandbox: Sandbox, repo: Path, finding: dict[str, Any],
            workdir: Path) -> PocRun:
    """Run a finding's PoC against a fresh copy of ``repo`` inside ``workdir``."""
    poc = _executable_poc(finding)
    if poc is None:
        kind = (finding.get("poc") or {}).get("kind")
        return PocRun(attempted=False, reason=f"poc kind {kind!r} is not executable")

    target, poc_path = _prepare_target(repo, workdir, poc)
    runner = _RUNNERS.get(poc_path.suffix)
    if runner is None:
        return PocRun(attempted=False, reason=f"no runner for {poc_path.suffix}")
    if shutil.which(runner[0]) is None:
        return PocRun(attempted=False, reason=f"runtime {runner[0]!r} not available")

    before = _snapshot(target, exclude={poc_path})
    demonstrated, output, rc, timed_out, enforced = _demonstrates(sandbox, target, poc_path, poc)
    integrity_ok = not _tampered(target, before, exclude={poc_path})

    reason = ""
    if not integrity_ok:
        reason = "PoC modified pre-existing source (tampering)"
        demonstrated = False
    elif timed_out:
        reason = "PoC timed out"
    elif not demonstrated:
        reason = f"PoC did not reproduce (exit {rc})"

    return PocRun(attempted=True, demonstrated=demonstrated, integrity_ok=integrity_ok,
                  returncode=rc, output=output, reason=reason, timed_out=timed_out,
                  enforced=enforced)


# ---- patch application --------------------------------------------------

def _looks_unified(patch: str) -> bool:
    return "@@" in patch or patch.lstrip().startswith(("--- ", "diff "))


_HUNK = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@(.*)$")


def recount_hunks(patch: str) -> str:
    """Rewrite each hunk header's line counts from the hunk body.

    Model-written diffs often carry the right start lines but miscounted
    lengths, which `git apply` rejects as a corrupt patch. Counts are derived
    from the lines actually present: context and blank lines count on both
    sides, ``-`` lines on the old side, ``+`` lines on the new side. Headers
    without start lines are left alone.
    """
    lines = patch.rstrip("\n").split("\n")
    out: list[str] = []
    i = 0
    while i < len(lines):
        m = _HUNK.match(lines[i])
        if not m:
            out.append(lines[i])
            i += 1
            continue
        body: list[str] = []
        i += 1
        while i < len(lines) and not lines[i].startswith(("@@", "--- ", "diff ")):
            body.append(lines[i] if lines[i] else " ")  # blank context lost its space
            i += 1
        old = sum(1 for b in body if b[0] in " -")
        new = sum(1 for b in body if b[0] in " +")
        out.append(f"@@ -{m.group(1)},{old} +{m.group(2)},{new} @@{m.group(3)}")
        out.extend(body)
    return "\n".join(out) + "\n"


def _git_apply(target: Path, patch: str) -> str | None:
    """Try `git apply` with -p1 then -p0; return the strip that worked, or None."""
    patch_file = target / ".openplow.patch"
    patch_file.write_text(patch if patch.endswith("\n") else patch + "\n", encoding="utf-8")
    try:
        for strip in ("-p1", "-p0"):
            proc = subprocess.run(
                ["git", "apply", "--unsafe-paths", strip, patch_file.name],
                check=False, cwd=str(target), capture_output=True, text=True,
            )
            if proc.returncode == 0:
                return strip
        return None
    finally:
        patch_file.unlink(missing_ok=True)


def _apply_unified(target: Path, patch: str) -> tuple[bool, str]:
    """Apply a real unified diff with `git apply`, trying -p1 then -p0. If that
    fails, retry once with the hunk headers' line counts recomputed."""
    if shutil.which("git") is None:
        return False, "git not available to apply unified diff"
    strip = _git_apply(target, patch)
    if strip:
        return True, f"git apply {strip}"
    fixed = recount_hunks(patch)
    if fixed != patch:
        strip = _git_apply(target, fixed)
        if strip:
            return True, f"git apply {strip} (hunk line counts recomputed)"
    return False, "git apply failed (-p1 and -p0)"


def _apply_snippet(target: Path, finding: dict[str, Any], patch: str) -> tuple[bool, str]:
    """Apply a simple -/+ snippet (no @@ headers) to the cited file by replacing
    the removed block with the added block."""
    loc = finding.get("location") or {}
    rel = (loc.get("file") or "").lstrip("./")
    if not rel:
        return False, "no location.file for snippet patch"
    path = target / rel
    if not path.exists():
        return False, f"cited file missing in copy: {rel}"

    removed, added = [], []
    for line in patch.splitlines():
        if line.startswith("-") and not line.startswith("---"):
            removed.append(line[1:])
        elif line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:])
    if not removed:
        return False, "snippet patch has no '-' lines to locate"

    src = path.read_text(encoding="utf-8")
    block = "\n".join(removed)
    if block not in src:
        return False, "removed block not found in cited file"
    path.write_text(src.replace(block, "\n".join(added), 1), encoding="utf-8")
    return True, "applied snippet patch"


def apply_patch(target: Path, finding: dict[str, Any]) -> tuple[bool, str]:
    """Apply the finding's patch to the copied tree. Returns (applied, reason)."""
    patch = finding.get("patch")
    if not patch:
        return False, "no patch"
    if _looks_unified(patch):
        return _apply_unified(target, patch)
    return _apply_snippet(target, finding, patch)


def run_patch_gate(sandbox: Sandbox, repo: Path, finding: dict[str, Any],
                   workdir: Path) -> PatchGate:
    """Reproduce -> patch -> must-not-reproduce. Only a clean flip passes."""
    poc = _executable_poc(finding)
    if poc is None:
        return PatchGate(attempted=False, reason="poc not executable")
    if not finding.get("patch"):
        return PatchGate(attempted=False, reason="no patch to gate")

    # Fresh copy for the "before" run so its artifacts never leak into "after".
    tb, pb = _prepare_target(repo, workdir / "before", poc)
    runner = _RUNNERS.get(pb.suffix)
    if runner is None or shutil.which(runner[0]) is None:
        return PatchGate(attempted=False, reason=f"no runtime for {pb.suffix}")

    before, *_ = _demonstrates(sandbox, tb, pb, poc)
    if not before:
        return PatchGate(attempted=True, reproduced_before=False,
                         reason="PoC did not reproduce before patch")

    # Separate fresh copy for the "after" run, patched.
    ta, pa = _prepare_target(repo, workdir / "after", poc)
    applied, areason = apply_patch(ta, finding)
    if not applied:
        return PatchGate(attempted=True, reproduced_before=True, patch_applied=False,
                         reason=f"patch did not apply: {areason}")

    after, *_ = _demonstrates(sandbox, ta, pa, poc)
    passed = not after
    reason = "fail->pass flip verified" if passed else "PoC still reproduces after patch"
    return PatchGate(attempted=True, reproduced_before=True, patch_applied=True,
                     reproduced_after=after, passed=passed, reason=reason)
