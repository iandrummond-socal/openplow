"""Phase 1 — Reconnaissance.

Maps the target's architecture and input surfaces, then lays out a coverage
ledger of ``(area x attack-class)`` cells and enqueues one hunt task per cell.

Better recon is the single biggest lever on false positives (Cloudflare's
validation rejection rate fell from 40% to 11% once recon gave hunters real
context), so the real implementation spends a frontier model here. The M1
scaffold does a deterministic structural pass so the rest of the pipeline has
a ledger to work from.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..context import RunContext

# The core attack classes, mirroring the skill's class files. A real run also
# derives repo-specific custom classes during recon.
ATTACK_CLASSES = [
    "web-protocol-and-auth",
    "memory-safety-and-binary",
    "ai-and-llm",
    "client-side",
    "supply-chain-and-release",
    "cloud-and-deployment",
    "protocols-rpc-and-messaging",
    "resource-exhaustion-and-availability",
    "data-isolation-and-lifecycle",
    "desktop-mobile-and-local-ipc",
]

# Directories that are never interesting attack surface.
_SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "__pycache__",
              ".venv", "venv", "target", ".idea", ".vscode"}

_SRC_SUFFIXES = {".py", ".js", ".ts", ".tsx", ".go", ".rs", ".c", ".cc", ".cpp",
                 ".h", ".hpp", ".java", ".rb", ".php", ".lua", ".sh"}


def _discover_areas(repo: Path) -> dict[str, dict[str, Any]]:
    """Group the repo into coarse areas (top-level code dirs), with file counts
    and the languages seen. Areas are the ledger's rows."""
    areas: dict[str, dict[str, Any]] = {}
    for path in repo.rglob("*"):
        if not path.is_file() or path.suffix not in _SRC_SUFFIXES:
            continue
        rel = path.relative_to(repo)
        if any(part in _SKIP_DIRS for part in rel.parts):
            continue
        area = rel.parts[0] if len(rel.parts) > 1 else "(root)"
        entry = areas.setdefault(area, {"files": 0, "languages": set()})
        entry["files"] += 1
        entry["languages"].add(path.suffix.lstrip("."))
    return areas


def run_task(ctx: RunContext, payload: dict[str, Any]) -> dict[str, Any]:
    """Produce architecture.md + coverage-ledger.json and enqueue hunts."""
    areas = _discover_areas(ctx.repo)

    if not areas:
        ctx.store.add_wish(ctx.run_id, ctx.repo_name, "recon",
                           "no source files discovered under recognised suffixes")

    # architecture.md — the shared context every hunter reads.
    arch_lines = [
        f"# Architecture — {ctx.repo_name}",
        "",
        "Areas discovered during reconnaissance:",
        "",
        "| Area | Files | Languages |",
        "| --- | --- | --- |",
    ]
    for area, info in sorted(areas.items()):
        langs = ", ".join(sorted(info["languages"]))
        arch_lines.append(f"| {area} | {info['files']} | {langs} |")
    (ctx.out_dir / "architecture.md").write_text("\n".join(arch_lines) + "\n")

    # coverage-ledger.json — one cell per (area x attack-class).
    ledger: list[dict[str, Any]] = []
    for area in sorted(areas):
        for cls in ATTACK_CLASSES:
            ledger.append({"area": area, "attack_class": cls, "status": "pending"})
    (ctx.out_dir / "coverage-ledger.json").write_text(json.dumps(ledger, indent=2) + "\n")

    # Enqueue a hunt per cell. The store dedups identical tasks.
    enqueued = 0
    for cell in ledger:
        task_id = f"hunt:{cell['area']}:{cell['attack_class']}"
        if ctx.store.add_task(task_id, ctx.run_id, ctx.repo_name, "hunt", payload=cell):
            enqueued += 1

    # Report runs as a finalization step in the orchestrator, after the queue
    # drains, so it always sees the full validated finding set.
    return {"areas": len(areas), "cells": len(ledger), "hunts_enqueued": enqueued}
