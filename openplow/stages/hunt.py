"""Phase 2 — Hunting.

A hunter takes one ``(area x attack-class)`` cell and tries to *break* the code,
not review it. Anything it files must carry a threat model (who the attacker is
and which boundary is crossed), a proof-of-concept that runs against the
untouched code, and a proposed patch — or it is not filed.

Findings stream into the store as ``needs_validation`` the moment they are
produced, so a crash loses only the task in flight. The validator stage, running
a *different* model, judges them later.

The M1 scaffold does not call a real model to find bugs; it emits zero findings
and records the cell as hunted, which lets the full producer/consumer loop run.
The real implementation builds the hunter prompt from the matching class file in
``skills/`` plus the recon context, and parses the model's findings against the
finding schema before persisting them.
"""

from __future__ import annotations

from typing import Any

from ..context import RunContext
from ..models import Outcome


def _build_prompt(ctx: RunContext, area: str, attack_class: str) -> tuple[str, str]:
    """Assemble (system, prompt) for a hunter. Kept deterministic and small."""
    system = (
        "You are an adversarial security hunter. Try to break the code, not review it. "
        "File a finding only with a threat model (attacker + boundary), a PoC that runs "
        "against the untouched code, and a proposed patch."
    )
    prompt = (
        f"Target area: {area}\n"
        f"Attack class: {attack_class}\n"
        f"Repo: {ctx.repo_name}\n\n"
        "Return findings as JSON matching the finding schema, or an empty list."
    )
    return system, prompt


def _parse_findings(text: str) -> list[dict[str, Any]]:
    """Parse a model response into finding dicts. The stub returns no findings;
    the real parser validates each against schemas/finding.schema.json."""
    if text.strip() == "STUB_OK":
        return []
    import json
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else []


def run_task(ctx: RunContext, payload: dict[str, Any]) -> dict[str, Any]:
    area = payload.get("area", "(root)")
    attack_class = payload.get("attack_class", "unknown")

    system, prompt = _build_prompt(ctx, area, attack_class)
    resp = ctx.finder.complete(system, prompt)

    if resp.outcome is Outcome.RETRYABLE:
        # Signal the orchestrator to retry by raising.
        raise RuntimeError(f"hunter transient failure: {resp.error or 'retryable body'}")
    if resp.outcome is Outcome.FATAL:
        ctx.store.add_wish(ctx.run_id, ctx.repo_name, "hunt",
                           f"hunter fatal on {area}/{attack_class}: {resp.error}")
        return {"area": area, "attack_class": attack_class, "findings": 0, "fatal": True}

    findings = _parse_findings(resp.text)
    filed = 0
    for i, finding in enumerate(findings):
        finding.setdefault("id", f"{area}:{attack_class}:{i}")
        finding["verdict"] = "needs_validation"
        finding.setdefault("attack_class", attack_class)
        finding["provenance"] = {
            "run_id": ctx.run_id, "repo": ctx.repo_name, "stage": "hunt",
            "finder_model": ctx.finder.name, "task_id": f"hunt:{area}:{attack_class}",
        }
        ctx.store.upsert_finding(ctx.run_id, ctx.repo_name, "hunt", finding)
        # Each new finding becomes a validation task.
        ctx.store.add_task(f"validate:{finding['id']}", ctx.run_id, ctx.repo_name,
                           "validate", payload={"finding_id": finding["id"]})
        filed += 1

    return {"area": area, "attack_class": attack_class, "findings": filed}
