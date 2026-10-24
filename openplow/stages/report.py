"""Phase 6 — Reporting.

A plain script, no model. It reads the verified records from the store and
writes human- and machine-readable output: REPORT.md, findings.json, and a
SARIF file so results can be surfaced in GitHub code scanning.
"""

from __future__ import annotations

import json
from typing import Any

from ..context import RunContext

_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note", None: "warning"}


def _to_sarif(ctx: RunContext, findings: list[dict[str, Any]]) -> dict[str, Any]:
    results = []
    for f in findings:
        loc = f.get("location") or {}
        results.append({
            "ruleId": f.get("attack_class", "unknown"),
            "level": _SARIF_LEVEL.get(f.get("severity")),
            "message": {"text": f.get("title", f.get("id", "finding"))},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": loc.get("file", "")},
                    "region": {"startLine": loc.get("line") or 1},
                }
            }],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "OpenPlow", "informationUri":
                     "https://github.com/iandrummond-socal/OpenPlow", "rules": []}},
            "results": results,
        }],
    }


def _is_duplicate(f: dict[str, Any]) -> bool:
    d = f.get("dedup")
    return bool(d) and not d.get("canonical", True)


def run_task(ctx: RunContext, payload: dict[str, Any]) -> dict[str, Any]:
    all_findings = ctx.store.findings(ctx.run_id)
    # Fold duplicates: the report counts one canonical finding per cluster.
    distinct = [f for f in all_findings if not _is_duplicate(f)]
    folded = len(all_findings) - len(distinct)

    confirmed = [f for f in distinct if f.get("verdict") == "confirmed"]
    needs = [f for f in distinct if f.get("verdict") == "needs_validation"]
    rejected = [f for f in distinct if f.get("verdict") == "rejected"]
    fix_verified = [f for f in confirmed if (f.get("fix") or {}).get("gate_passed")]

    (ctx.out_dir / "findings.json").write_text(json.dumps(all_findings, indent=2) + "\n")
    (ctx.out_dir / "openplow.sarif").write_text(
        json.dumps(_to_sarif(ctx, confirmed + needs), indent=2) + "\n")

    lines = [
        f"# OpenPlow report — {ctx.repo_name}",
        "",
        f"- Run: `{ctx.run_id}`",
        f"- Finder model: `{ctx.finder.name}`  ·  Validator model: `{ctx.validator.name}`",
        "",
        "## Summary",
        "",
        f"- Confirmed: {len(confirmed)}",
        f"- Fix verified (fail->pass patch gate): {len(fix_verified)}",
        f"- Needs validation: {len(needs)}",
        f"- Rejected: {len(rejected)}",
        f"- Duplicates folded: {folded}",
        "",
    ]
    if confirmed:
        lines += ["## Confirmed findings", ""]
        for f in confirmed:
            loc = f.get("location") or {}
            lines.append(f"### {f.get('title', f['id'])}")
            lines.append(f"- Class: {f.get('attack_class')}  ·  Severity: {f.get('severity')}")
            lines.append(f"- Location: `{loc.get('file')}:{loc.get('line', '')}`")
            fix = f.get("fix") or {}
            if fix:
                mark = "yes" if fix.get("gate_passed") else "no"
                lines.append(f"- Fix verified: {mark} ({fix.get('reason', '')})")
            lines.append("")

    usage = ctx.store.usage_by_model(ctx.run_id)
    if usage:
        from .. import pricing
        lines += ["## Cost (estimated)", "",
                  "| Role | Model | Calls | Input | Output | Est. $ |",
                  "| --- | --- | --- | --- | --- | --- |"]
        total = 0.0
        for u in usage:
            usg = pricing.Usage(u["input_tokens"], u["output_tokens"],
                                u["cache_read"], u["cache_creation"])
            cost = pricing.estimate_cost(u["model"], usg)
            total += cost or 0.0
            cost_str = f"${cost:.4f}" if cost is not None else "n/a"
            lines.append(f"| {u['role']} | {u['model']} | {u['calls']} | "
                         f"{u['input_tokens']} | {u['output_tokens']} | {cost_str} |")
        lines.append("")
        lines.append(f"**Estimated total: ${total:.4f}**")
        lines.append("")

    wishes = ctx.store.wishes(ctx.run_id)
    if wishes:
        lines += ["## Wishlist (what hunters needed)", ""]
        for w in wishes:
            lines.append(f"- [{w['stage']}] {w['item']}")
        lines.append("")

    (ctx.out_dir / "REPORT.md").write_text("\n".join(lines) + "\n")

    return {"confirmed": len(confirmed), "fix_verified": len(fix_verified),
            "needs_validation": len(needs), "rejected": len(rejected),
            "duplicates_folded": folded, "out_dir": str(ctx.out_dir)}
