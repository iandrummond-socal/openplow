"""Phase 2 — Hunting.

A hunter takes one ``(area x attack-class)`` cell and tries to *break* the code,
not review it. Anything it files must carry a threat model (who the attacker is
and which boundary is crossed), a proof-of-concept that runs against the
untouched code, and a proposed patch — or it is not filed.

The prompt is assembled from the matching class file in the vendored skill plus
the recon context (architecture.md) and a listing of the target area's files.
Model output is parsed and schema-checked before anything is persisted; a
finding that does not parse or is missing required fields is dropped and logged
to the wishlist rather than stored half-formed.

Findings stream into the store as ``needs_validation`` the moment they are
produced, so a crash loses only the task in flight. The validator stage, running
a *different* model, judges them later.

With the stub adapter no model is called, so no findings are produced and the
full producer/consumer loop still runs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .. import findings as findings_mod
from .. import skill_loader
from ..context import RunContext
from ..models import Outcome

# How much of the class file and architecture to inject, to keep context small.
_CLASS_PROMPT_CHARS = 8000
_ARCH_CHARS = 4000
_MAX_FILES_LISTED = 60

_SRC_SUFFIXES = {".py", ".js", ".ts", ".tsx", ".go", ".rs", ".c", ".cc", ".cpp",
                 ".h", ".hpp", ".java", ".rb", ".php", ".lua", ".sh"}

_SYSTEM = (
    "You are an adversarial security hunter auditing a codebase. Try to BREAK the "
    "code, not review it. File a finding only when you can name the attacker and the "
    "trust boundary crossed, provide a proof of concept that runs against the "
    "UNTOUCHED code, and propose a patch. Do not invent facts. If you find nothing "
    "real, return an empty list. Never edit source to make an exploit work.\n\n"
    "Return ONLY a JSON array of findings in a ```json fenced block. Each finding "
    "must have: id, verdict (always \"needs_validation\"), title, attack_class, "
    "threat_model {attacker, boundary}, location {file, line, symbol}, description, "
    "poc {kind, content, observed}, patch."
)


def _area_files(repo: Path, area: str) -> list[str]:
    """Repo-relative source files that belong to an area."""
    base = repo if area == "(root)" else repo / area
    out: list[str] = []
    if not base.exists():
        return out
    for path in base.rglob("*"):
        if path.is_file() and path.suffix in _SRC_SUFFIXES:
            out.append(str(path.relative_to(repo)))
            if len(out) >= _MAX_FILES_LISTED:
                break
    return out


def _build_prompt(ctx: RunContext, area: str, attack_class: str,
                  depth: int = 1) -> tuple[str, str]:
    """Assemble (system, prompt) for a hunter from the skill + recon context."""
    class_prompt = skill_loader.load_class_prompt(attack_class)
    if class_prompt is None:
        class_prompt = f"(No vendored class file for {attack_class}; use general methodology.)"
        ctx.store.add_wish(ctx.run_id, ctx.repo_name, "hunt",
                           f"missing vendored skill class file for {attack_class}")

    arch_path = ctx.out_dir / "architecture.md"
    arch = arch_path.read_text(encoding="utf-8") if arch_path.exists() else ""
    files = _area_files(ctx.repo, area)

    prompt = (
        f"# Target\nRepo: {ctx.repo_name}\nArea: {area}\nAttack class: {attack_class}\n\n"
        f"# Architecture context\n{arch[:_ARCH_CHARS]}\n\n"
        f"# Files in this area ({len(files)} shown)\n" + "\n".join(files) + "\n\n"
        f"# Attack-class methodology\n{class_prompt[:_CLASS_PROMPT_CHARS]}\n\n"
        "Hunt this area for the attack class above. Return a JSON array of findings."
    )
    if depth > 1:
        prompt += (
            f"\n\nThis is gapfill pass {depth}: a previous hunt of this cell found "
            "nothing. Look harder and from a different angle — chained or multi-step "
            "paths, edge cases, and assumptions the obvious review would skip."
        )
    return _SYSTEM, prompt


def _parse_findings(text: str) -> list[dict[str, Any]]:
    if text.strip() == "STUB_OK":
        return []
    return findings_mod.extract_json(text)


def run_task(ctx: RunContext, payload: dict[str, Any]) -> dict[str, Any]:
    area = payload.get("area", "(root)")
    attack_class = payload.get("attack_class", "unknown")
    depth = int(payload.get("depth", 1))

    system, prompt = _build_prompt(ctx, area, attack_class, depth)
    resp = ctx.finder.complete(system, prompt, max_tokens=8192)

    if resp.outcome is Outcome.RETRYABLE:
        # Signal the orchestrator to retry by raising.
        raise RuntimeError(f"hunter transient failure: {resp.error or 'retryable body'}")
    if resp.outcome is Outcome.FATAL:
        ctx.store.add_wish(ctx.run_id, ctx.repo_name, "hunt",
                           f"hunter fatal on {area}/{attack_class}: {resp.error}")
        return {"area": area, "attack_class": attack_class, "findings": 0, "fatal": True}

    parsed = _parse_findings(resp.text)
    existing_ids = {f["id"] for f in ctx.store.findings(ctx.run_id)}
    filed = 0
    dropped = 0
    skipped = 0
    for i, finding in enumerate(parsed):
        finding.setdefault("id", f"{area}:{attack_class}:{i}")
        # First report of an id wins: a later (e.g. gapfill) pass must not
        # overwrite an already-stored/validated finding back to needs_validation.
        if finding["id"] in existing_ids:
            skipped += 1
            continue
        finding["verdict"] = "needs_validation"
        finding.setdefault("attack_class", attack_class)
        finding["provenance"] = {
            "run_id": ctx.run_id, "repo": ctx.repo_name, "stage": "hunt",
            "finder_model": ctx.finder.name, "task_id": f"hunt:{area}:{attack_class}",
        }
        problems = findings_mod.validate_finding(finding)
        if problems:
            dropped += 1
            ctx.store.add_wish(ctx.run_id, ctx.repo_name, "hunt",
                               f"dropped malformed finding {finding['id']}: {problems[0]}")
            continue
        ctx.store.upsert_finding(ctx.run_id, ctx.repo_name, "hunt", finding)
        # Each new finding becomes a validation task.
        ctx.store.add_task(f"validate:{finding['id']}", ctx.run_id, ctx.repo_name,
                           "validate", payload={"finding_id": finding["id"]})
        filed += 1

    return {"area": area, "attack_class": attack_class, "findings": filed,
            "dropped": dropped, "skipped": skipped}
