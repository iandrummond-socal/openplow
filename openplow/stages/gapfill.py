"""Gapfill.

Coverage is measured over ``(area x attack-class)`` cells. A cell that produced
no surviving finding is *thin* — either there is nothing there, or the hunter
did not look hard enough. Gapfill re-queues a deeper hunt for every thin cell;
the orchestrator drains those new hunts, and the loop repeats up to a cap. This
is the main cost-to-coverage lever (Cloudflare put ~half the initial hunt's cost
into gapfill passes).

"Thin" here means zero non-rejected findings in the cell. Each gapfill hunt
carries a higher ``depth`` in its payload so the hunter can push harder, and so
the task is distinct from the first-round hunt (the store dedups identical
tasks).
"""

from __future__ import annotations

import json
from typing import Any

from ..context import RunContext


def _cells_from_ledger(ctx: RunContext) -> list[dict[str, str]]:
    ledger_path = ctx.out_dir / "coverage-ledger.json"
    if not ledger_path.exists():
        return []
    return [
        {"area": c["area"], "attack_class": c["attack_class"]}
        for c in json.loads(ledger_path.read_text(encoding="utf-8"))
    ]


def _findings_by_cell(ctx: RunContext) -> dict[tuple[str, str], int]:
    """Count non-rejected findings per (area, attack_class), keyed off provenance."""
    counts: dict[tuple[str, str], int] = {}
    for f in ctx.store.findings(ctx.run_id):
        if f.get("verdict") == "rejected":
            continue
        task_id = (f.get("provenance") or {}).get("task_id", "")
        # task_id looks like "hunt:<area>:<attack_class>"
        parts = task_id.split(":")
        if len(parts) >= 3 and parts[0] == "hunt":
            key = (parts[1], parts[2])
            counts[key] = counts.get(key, 0) + 1
    return counts


def run_task(ctx: RunContext, payload: dict[str, Any]) -> dict[str, Any]:
    round_no = int(payload.get("round", 1))
    cells = _cells_from_ledger(ctx)
    counts = _findings_by_cell(ctx)

    enqueued = 0
    for cell in cells:
        key = (cell["area"], cell["attack_class"])
        if counts.get(key, 0) > 0:
            continue  # cell already yielded something; not thin
        task_id = f"gapfill:{round_no}:{cell['area']}:{cell['attack_class']}"
        if ctx.store.add_task(task_id, ctx.run_id, ctx.repo_name, "hunt",
                              payload={**cell, "depth": round_no + 1}):
            enqueued += 1

    return {"round": round_no, "thin_cells": len(cells) - len(counts),
            "enqueued": enqueued}
