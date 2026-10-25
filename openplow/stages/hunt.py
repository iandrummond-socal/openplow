"""Phase 2 — Hunting.

A hunter takes one ``(area x attack-class)`` cell and tries to *break* the code,
not review it. Anything it files must carry a threat model (who the attacker is
and which boundary is crossed), a proof-of-concept that runs against the
untouched code, and a proposed patch — or it is not filed.

The prompt is assembled from the matching class file in the vendored skill plus
the recon context (architecture.md) and a listing of the target area's files.
A finder that supports tool use also gets read-only ``list_files`` /
``read_file`` / ``grep`` tools over the checkout, so it can read the code it is
hunting in rather than guess from file names.

Every hunter call's raw output (prompt, final text, per-turn tool calls, stop
reason, refusal details and which model served it, what was parsed and dropped) is written to
``<out>/transcripts/hunt/<cell>.json`` so a miss can be diagnosed afterwards.
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

import json
import re
from pathlib import Path
from typing import Any

from .. import findings as findings_mod
from .. import skill_loader
from ..context import RunContext
from ..models import Outcome, served_model
from ..repo_tools import RepoTools

# How much of the class file and architecture to inject, to keep context small.
_CLASS_PROMPT_CHARS = 8000
_ARCH_CHARS = 4000
_MAX_FILES_LISTED = 60
# Tool rounds a hunter may spend reading code before it must answer.
_MAX_TOOL_ROUNDS = 30

_TOOLS_NOTE = (
    "\n\nYou have read-only tools over the target repository: list_files, read_file "
    "and grep (paths relative to the repo root). Read the code before you judge it, "
    "and ground every finding's location in lines you actually read."
)

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
    "poc {kind, content, observed}, patch. Optionally add weakness: your own label "
    "for the bug (e.g. a CWE); attack_class is set to the class you were asked to hunt.\n\n"
    "poc.kind is the PoC's role, not its language, and must be one of: "
    "\"test\" or \"script\" (a Python file, run with python3 from the repo root "
    "against the untouched code; it must exit 0 and print the \"observed\" text), "
    "\"input\" (a malicious input to feed the target) or \"trace\" (a step-by-step "
    "path through the code). Only test and script PoCs are executed and can verify "
    "a patch, so use one of them whenever the issue can be demonstrated in Python. "
    "\"observed\" is matched as an exact substring of the PoC's output, so make it a "
    "fixed marker the PoC always prints when the issue reproduces (e.g. \"ESCAPED\"): "
    "no placeholders, temporary paths, timestamps or other values that change per run."
    "\n\npatch must be a unified diff that applies with `git apply` from the repo root: "
    "--- a/<path> and +++ b/<path> headers, and every hunk header with line numbers "
    "(@@ -start,count +start,count @@) and context lines copied exactly from the file."
)

# Language names a model may put in poc.kind. Only Python maps cleanly: test and
# script PoCs are run with python3, so another language would run wrongly.
_POC_KIND_ALIASES = {"python": "script", "python3": "script", "py": "script"}


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
                  depth: int = 1, *, tools: bool = False) -> tuple[str, str]:
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
    return (_SYSTEM + _TOOLS_NOTE if tools else _SYSTEM), prompt


def _parse_findings(text: str) -> list[dict[str, Any]]:
    if text.strip() == "STUB_OK":
        return []
    return findings_mod.extract_json(text)


def run_task(ctx: RunContext, payload: dict[str, Any]) -> dict[str, Any]:
    area = payload.get("area", "(root)")
    attack_class = payload.get("attack_class", "unknown")
    depth = int(payload.get("depth", 1))

    use_tools = ctx.finder.supports_tools
    system, prompt = _build_prompt(ctx, area, attack_class, depth, tools=use_tools)
    if use_tools:
        resp = ctx.finder.complete_with_tools(system, prompt, RepoTools(ctx.repo),
                                              max_tokens=8192, max_rounds=_MAX_TOOL_ROUNDS)
    else:
        resp = ctx.finder.complete(system, prompt, max_tokens=8192)

    record: dict[str, Any] = {
        "task": payload, "finder": ctx.finder.name, "outcome": resp.outcome.value,
        "error": resp.error, "stop_reason": (resp.raw or {}).get("stop_reason"),
        "tool_rounds": (resp.raw or {}).get("tool_rounds"),
        "stop_details": (resp.raw or {}).get("stop_details"),
        "served_by": (resp.raw or {}).get("served_by"),
        "fallbacks": (resp.raw or {}).get("fallbacks"),
        "system": system, "prompt": prompt, "text": resp.text,
        "transcript": (resp.raw or {}).get("transcript"),
    }
    transcript_path = _write_transcript(ctx, area, attack_class, depth, record)

    if resp.outcome is Outcome.RETRYABLE:
        # Signal the orchestrator to retry by raising.
        raise RuntimeError(f"hunter transient failure: {resp.error or 'retryable body'}")
    if resp.outcome is Outcome.FATAL:
        ctx.store.add_wish(ctx.run_id, ctx.repo_name, "hunt",
                           f"hunter fatal on {area}/{attack_class}: {resp.error}")
        return {"area": area, "attack_class": attack_class, "findings": 0, "fatal": True}

    parsed = _parse_findings(resp.text)
    refused = record["stop_reason"] == "refusal"
    if refused:
        # A safety-classifier decline (after any fallback) is not "found nothing".
        category = (record["stop_details"] or {}).get("category")
        ctx.store.add_wish(ctx.run_id, ctx.repo_name, "hunt",
                           f"hunter refused on {area}/{attack_class} (category: {category}); "
                           f"see {transcript_path}")
    elif not parsed and resp.text.strip() and resp.text.strip() != "STUB_OK" \
            and not _is_empty_answer(resp.text):
        ctx.store.add_wish(ctx.run_id, ctx.repo_name, "hunt",
                           f"unparseable hunter output on {area}/{attack_class}; "
                           f"see {transcript_path}")
    if record["stop_reason"] == "max_tokens":
        ctx.store.add_wish(ctx.run_id, ctx.repo_name, "hunt",
                           f"hunter output truncated (max_tokens) on {area}/{attack_class}")
    record["parsed"] = len(parsed)
    record["drops"] = []
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
        _normalize_poc_kind(finding)
        finding["verdict"] = "needs_validation"
        # The cell's class is the finding's class; the model's own label (often a
        # free-text CWE description) is kept as the weakness.
        label = finding.get("attack_class")
        if isinstance(label, str) and label != attack_class and not finding.get("weakness"):
            finding["weakness"] = label
        finding["attack_class"] = attack_class
        finding["provenance"] = {
            "run_id": ctx.run_id, "repo": ctx.repo_name, "stage": "hunt",
            "finder_model": ctx.finder.name, "task_id": f"hunt:{area}:{attack_class}",
            # Differs from finder_model when a refusal fell back to another model.
            "served_by": served_model(resp),
        }
        problems = findings_mod.validate_finding(finding)
        if problems:
            dropped += 1
            record["drops"].append({"id": finding["id"], "problems": problems})
            ctx.store.add_wish(ctx.run_id, ctx.repo_name, "hunt",
                               f"dropped malformed finding {finding['id']}: {problems[0]}")
            continue
        ctx.store.upsert_finding(ctx.run_id, ctx.repo_name, "hunt", finding)
        # Each new finding becomes a validation task.
        ctx.store.add_task(f"validate:{finding['id']}", ctx.run_id, ctx.repo_name,
                           "validate", payload={"finding_id": finding["id"]})
        filed += 1

    record.update(filed=filed, dropped=dropped, skipped=skipped)
    _write_transcript(ctx, area, attack_class, depth, record)
    return {"area": area, "attack_class": attack_class, "findings": filed,
            "dropped": dropped, "skipped": skipped}


def _normalize_poc_kind(finding: dict[str, Any]) -> None:
    """Map a Python language name in poc.kind to the "script" role."""
    poc = finding.get("poc")
    if isinstance(poc, dict) and isinstance(poc.get("kind"), str):
        poc["kind"] = _POC_KIND_ALIASES.get(poc["kind"].strip().lower(), poc["kind"])


def _is_empty_answer(text: str) -> bool:
    """True when the model explicitly answered with an empty findings array."""
    body = re.sub(r"```(?:json)?|```", "", text).strip()
    return body.endswith("[]") and "{" not in body


def _write_transcript(ctx: RunContext, area: str, attack_class: str, depth: int,
                      record: dict[str, Any]) -> Path:
    """Persist one hunter call's raw output for later diagnosis."""
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", f"{area}__{attack_class}__d{depth}")
    path = ctx.out_dir / "transcripts" / "hunt" / f"{name}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
    return path
