"""Phase 3 — Validation.

Three checks, and the validator can never file a finding itself:

* **Pass 1, deterministic.** The cited file exists; the finding has a threat
  model; a PoC is present. A failure here rejects the finding without spending a
  model or the sandbox.
* **PoC execution.** The PoC runs in the sandbox against a pristine copy of the
  target (``openplow.poc``). Reproduction against untouched code is the ground
  truth; a PoC that tampers with source is rejected outright.
* **Pass 2, adversarial.** A *fresh, isolated* agent — a different model from the
  finder — tries to disprove the finding and returns an explicit verdict. A
  validator that supports tool use gets the same read-only repo tools as the
  finder, so it checks the claim against the code rather than the finding's
  own quotes; its raw output goes to ``<out>/transcripts/validate/<id>.json``.

The verdict combines them: a tampering PoC or one that fails to reproduce is
rejected; an executed PoC that reproduces is confirmed unless the adversarial
model disproves it; a non-executable PoC falls back to the model verdict.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .. import poc as poc_mod
from ..context import RunContext
from ..models import ModelResponse, Outcome, served_model
from ..repo_tools import RepoTools

# Tool rounds the validator may spend reading code before it must answer.
_MAX_TOOL_ROUNDS = 30

_TOOLS_NOTE = (
    "\n\nYou have read-only tools over the target repository: list_files, read_file "
    "and grep (paths relative to the repo root). Check the finding against the actual "
    "code — do not take its quoted code or line numbers on trust."
)


def _write_transcript(ctx: RunContext, finding: dict[str, Any], system: str, prompt: str,
                      resp: ModelResponse) -> None:
    """Persist the validator's raw output for later diagnosis."""
    raw = resp.raw or {}
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", str(finding.get("id", "unknown")))
    path = ctx.out_dir / "transcripts" / "validate" / f"{name}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "finding_id": finding.get("id"), "validator": ctx.validator.name,
        "outcome": resp.outcome.value, "error": resp.error,
        "stop_reason": raw.get("stop_reason"), "tool_rounds": raw.get("tool_rounds"),
        "stop_details": raw.get("stop_details"), "served_by": raw.get("served_by"),
        "fallbacks": raw.get("fallbacks"),
        "system": system, "prompt": prompt, "text": resp.text,
        "transcript": raw.get("transcript"),
    }, indent=2, default=str), encoding="utf-8")


def _pass1_deterministic(ctx: RunContext, finding: dict[str, Any]) -> list[str]:
    """Return a list of reasons the finding fails deterministic checks (empty = pass)."""
    problems: list[str] = []

    loc = finding.get("location") or {}
    rel = loc.get("file")
    if not rel:
        problems.append("no location.file")
    elif not (ctx.repo / rel).exists():
        problems.append(f"cited file does not exist: {rel}")

    tm = finding.get("threat_model") or {}
    if not tm.get("attacker") or not tm.get("boundary"):
        problems.append("incomplete threat model (need attacker + boundary)")

    if not finding.get("poc"):
        # No PoC => treated as fake. This is the core false-positive control.
        problems.append("no proof of concept")

    return problems


def _pass2_adversarial(ctx: RunContext, finding: dict[str, Any]) -> tuple[str, str, str | None]:
    """Ask a fresh validator model to disprove the finding.

    Returns ``(verdict, notes, served_by)`` where verdict is one of ``confirmed``,
    ``rejected``, or ``needs_validation`` and ``served_by`` is the model that
    wrote the verdict, when known. The validator must end with a line
    ``VERDICT: <value>``. The stub cannot judge, so a finding that clears Pass 1
    stays ``needs_validation`` — it is never auto-confirmed without a real
    adversarial check."""
    system = (
        "You are an adversarial validator. You did NOT find this issue and you cannot "
        "file findings. Try to DISPROVE it: trace a real attacker path to the reported "
        "boundary failure, and look for a layer that already prevents it. Decide whether "
        "the boundary failure actually holds against the untouched code.\n\n"
        "End your reply with exactly one line:\n"
        "VERDICT: confirmed   (the boundary failure holds and is reachable)\n"
        "VERDICT: rejected    (disproved, or defended by another layer)\n"
        "VERDICT: needs_validation (cannot resolve an exact fact)"
    )
    prompt = f"Finding to disprove:\n{finding}"
    if ctx.validator.supports_tools:
        system += _TOOLS_NOTE
        resp = ctx.validator.complete_with_tools(system, prompt, RepoTools(ctx.repo),
                                                 max_tokens=8192, max_rounds=_MAX_TOOL_ROUNDS)
    else:
        resp = ctx.validator.complete(system, prompt)
    _write_transcript(ctx, finding, system, prompt, resp)
    if (resp.raw or {}).get("stop_reason") == "refusal":
        category = ((resp.raw or {}).get("stop_details") or {}).get("category")
        ctx.store.add_wish(ctx.run_id, ctx.repo_name, "validate",
                           f"validator refused on {finding.get('id')} (category: {category})")
    if resp.outcome is Outcome.RETRYABLE:
        raise RuntimeError("validator transient failure")
    if resp.text.strip() == "STUB_OK":
        return "needs_validation", "stub validator: no adversarial judgment available", None

    verdict = _parse_verdict(resp.text)
    return verdict, resp.text[:800], served_model(resp)


def _parse_verdict(text: str) -> str:
    """Pull the VERDICT line out of the validator's reply; default to open."""
    for line in reversed(text.splitlines()):
        low = line.strip().lower()
        if low.startswith("verdict:"):
            value = low.split(":", 1)[1].strip()
            if value in ("confirmed", "rejected", "needs_validation"):
                return value
    # No explicit verdict: fall back to conservative keyword reading.
    low = text.lower()
    if "false positive" in low or "disproved" in low:
        return "rejected"
    return "needs_validation"


def run_task(ctx: RunContext, payload: dict[str, Any]) -> dict[str, Any]:
    finding_id = payload["finding_id"]
    matches = [f for f in ctx.store.findings(ctx.run_id) if f.get("id") == finding_id]
    if not matches:
        return {"finding_id": finding_id, "verdict": "missing"}
    finding = matches[0]

    problems = _pass1_deterministic(ctx, finding)
    if problems:
        finding["verdict"] = "rejected"
        finding["validation"] = {"checked_by": "deterministic", "disproof_attempted": False,
                                 "notes": "; ".join(problems)}
        ctx.store.upsert_finding(ctx.run_id, ctx.repo_name, "validate", finding)
        return {"finding_id": finding_id, "verdict": "rejected", "reasons": problems}

    # PoC execution against a pristine copy — the ground-truth check.
    run = poc_mod.run_poc(ctx.sandbox, ctx.repo, finding,
                          ctx.out_dir / "scratch" / finding_id)

    if run.attempted and not run.integrity_ok:
        return _reject(ctx, finding, finding_id, f"poc-execution: {run.reason}", run)
    if run.attempted and not run.demonstrated:
        return _reject(ctx, finding, finding_id, f"poc-execution: {run.reason}", run)

    # Adversarial model pass (can disprove even an executed PoC).
    verdict, notes, served_by = _pass2_adversarial(ctx, finding)

    if run.attempted and run.demonstrated:
        # Reproduced against untouched code. Confirm unless the model disproved it.
        verdict = "rejected" if verdict == "rejected" else "confirmed"

    finding["verdict"] = verdict
    if verdict != "confirmed":
        # Only a confirmed finding keeps a severity; clear any the finder set.
        finding["severity"] = None
    finding["validation"] = {
        "checked_by": ctx.validator.name, "served_by": served_by,
        "disproof_attempted": True, "notes": notes,
        "poc_attempted": run.attempted, "poc_demonstrated": run.demonstrated,
        "poc_reason": run.reason, "poc_enforced": run.enforced,
    }

    # Fail->pass patch gate on confirmed findings that ship a patch.
    fix_verified = False
    if verdict == "confirmed" and finding.get("patch"):
        gate = poc_mod.run_patch_gate(ctx.sandbox, ctx.repo, finding,
                                      ctx.out_dir / "scratch" / finding_id / "gate")
        fix_verified = gate.passed
        finding["fix"] = {
            "gate_passed": gate.passed, "reproduced_before": gate.reproduced_before,
            "patch_applied": gate.patch_applied, "reproduced_after": gate.reproduced_after,
            "reason": gate.reason,
        }

    ctx.store.upsert_finding(ctx.run_id, ctx.repo_name, "validate", finding)
    return {"finding_id": finding_id, "verdict": finding["verdict"],
            "poc_demonstrated": run.demonstrated, "fix_verified": fix_verified}


def _reject(ctx: RunContext, finding: dict[str, Any], finding_id: str,
            reason: str, run: poc_mod.PocRun) -> dict[str, Any]:
    finding["verdict"] = "rejected"
    finding["severity"] = None
    finding["validation"] = {"checked_by": "poc-execution", "disproof_attempted": True,
                             "notes": reason, "poc_attempted": run.attempted,
                             "poc_demonstrated": run.demonstrated,
                             "poc_enforced": run.enforced}
    ctx.store.upsert_finding(ctx.run_id, ctx.repo_name, "validate", finding)
    return {"finding_id": finding_id, "verdict": "rejected", "reasons": [reason]}
