"""Running a finding's proof of concept against the untouched codebase.

The core false-positive control: a finding with no PoC that actually reproduces
against the *untouched* code is treated as fake. Two things are checked here:

1. **Reproduction.** The PoC runs in the sandbox against a pristine copy of the
   target and demonstrates the issue (exit 0, and any declared ``observed``
   marker appears in the output).
2. **Integrity.** Agents sometimes edit source to make an exploit work. We hash
   the target's source before and after the run; if any pre-existing file
   changed, the PoC is rejected as tampered regardless of its exit code.

Only PoCs of kind ``test`` or ``script`` are executed. ``input`` and ``trace``
PoCs are not auto-run (no generic harness), so execution is reported as not
attempted and the model's adversarial judgment decides.
"""

from __future__ import annotations

import hashlib
import shutil
from dataclasses import dataclass
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


def _hash_tree(root: Path, exclude: set[Path]) -> str:
    """Stable hash of every source file under root, except the given paths."""
    h = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path in exclude:
            continue
        rel = path.relative_to(root)
        if any(part in {".git", "node_modules", "__pycache__"} for part in rel.parts):
            continue
        h.update(str(rel).encode())
        h.update(path.read_bytes())
    return h.hexdigest()


def _poc_filename(poc: dict[str, Any]) -> str:
    if poc.get("path"):
        return Path(poc["path"]).name
    ext = {"test": ".py", "script": ".py"}.get(poc.get("kind", ""), ".txt")
    return f"openplow_poc{ext}"


def run_poc(sandbox: Sandbox, repo: Path, finding: dict[str, Any],
            workdir: Path) -> PocRun:
    """Run a finding's PoC against a fresh copy of ``repo`` inside ``workdir``."""
    poc = finding.get("poc") or {}
    kind = poc.get("kind")
    if kind not in ("test", "script"):
        return PocRun(attempted=False, reason=f"poc kind {kind!r} is not executable")
    if not poc.get("content") and not poc.get("path"):
        return PocRun(attempted=False, reason="poc has no content or path")

    target = workdir / "target"
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(repo, target, ignore=_IGNORE)

    poc_path = target / _poc_filename(poc)
    if poc.get("content"):
        poc_path.write_text(poc["content"], encoding="utf-8")
    # else: the PoC is expected to already exist in the copied tree at poc["path"].

    runner = _RUNNERS.get(poc_path.suffix)
    if runner is None:
        return PocRun(attempted=False, reason=f"no runner for {poc_path.suffix}")
    if shutil.which(runner[0]) is None:
        return PocRun(attempted=False, reason=f"runtime {runner[0]!r} not available")

    before = _hash_tree(target, exclude={poc_path})
    result = sandbox.run([*runner, poc_path.name], cwd=target)
    after = _hash_tree(target, exclude={poc_path})

    integrity_ok = before == after
    output = (result.stdout + result.stderr)[-4000:]
    observed = poc.get("observed")
    demonstrated = (
        result.returncode == 0
        and (observed is None or observed in output)
    )

    reason = ""
    if not integrity_ok:
        reason = "PoC modified pre-existing source (tampering)"
        demonstrated = False
    elif result.timed_out:
        reason = "PoC timed out"
    elif not demonstrated:
        reason = f"PoC did not reproduce (exit {result.returncode})"

    return PocRun(attempted=True, demonstrated=demonstrated, integrity_ok=integrity_ok,
                  returncode=result.returncode, output=output, reason=reason)
