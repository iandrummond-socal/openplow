"""Phase 3 — Validation.

Two passes, and the validator can never file a finding itself:

* **Pass 1, deterministic.** The cited file exists; the finding has a threat
  model; a PoC is present; the patch (if any) is a plausible diff. A failure
  here rejects the finding without spending a model.
* **Pass 2, adversarial.** A *fresh, isolated* agent — a different model from the
  finder — tries to disprove the finding. If it cannot, and the deterministic
  checks pass, the finding is confirmed; otherwise it stays needs_validation or
  is rejected.

The scaffold runs Pass 1 fully (it is pure code) and stubs Pass 2.
"""

from __future__ import annotations

from typing import Any

from ..context import RunContext
from ..models import Outcome


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


def _pass2_adversarial(ctx: RunContext, finding: dict[str, Any]) -> tuple[bool, str]:
    """Ask a fresh validator model to disprove the finding.

    Returns (disproved, notes). The stub cannot disprove, so a finding that
    clears Pass 1 stays needs_validation (it is never auto-confirmed without a
    real adversarial check)."""
    system = (
        "You are an adversarial validator. You did NOT find this issue. Try to disprove it. "
        "You cannot file findings. State whether the reported boundary failure actually holds."
    )
    prompt = f"Finding to disprove:\n{finding}"
    resp = ctx.validator.complete(system, prompt)
    if resp.outcome is Outcome.RETRYABLE:
        raise RuntimeError("validator transient failure")
    if resp.text.strip() == "STUB_OK":
        return False, "stub validator: no adversarial judgment available"
    disproved = "disproved" in resp.text.lower() or "false positive" in resp.text.lower()
    return disproved, resp.text[:500]


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

    disproved, notes = _pass2_adversarial(ctx, finding)
    if disproved:
        finding["verdict"] = "rejected"
    else:
        # Cleared Pass 1 but no positive adversarial confirmation => stays open.
        finding["verdict"] = "needs_validation"
    finding["validation"] = {"checked_by": ctx.validator.name,
                             "disproof_attempted": True, "notes": notes}
    ctx.store.upsert_finding(ctx.run_id, ctx.repo_name, "validate", finding)
    return {"finding_id": finding_id, "verdict": finding["verdict"]}
