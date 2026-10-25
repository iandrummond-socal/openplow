"""Dedup.

The same root cause surfaces more than once — across attack classes, across
gapfill passes, and (later) across repos. String or path matching is not enough
at scale, but a deterministic first cut goes a long way: group findings by a
**root-cause key** — file, symbol (or line bucket) and weakness — then keep one
canonical finding per cluster and fold the rest.

The weakness is the first CWE id in the finding's ``weakness`` label (else its
title or description), so one bug reported from several attack-class angles
folds together while a different bug in the same function (say CWE-22 path
traversal and CWE-409 decompression bomb in one ``extract()``) stays separate.
A finding that names no CWE falls back to its attack class. The hunt cell's
class and the free-text trust boundary are deliberately not in the key: both
differ between reports of the same bug.

The key is stable across runs, so the same bug keeps the same cluster id from
one run to the next (what Cloudflare calls a stable cross-run key). A later wave
can add an agent pass over the borderline clusters this misses.

This stage only *marks* findings — it never deletes them. Each finding gets a
``dedup`` block: the ``key``, whether it is the ``canonical`` one, and the
``cluster_size``. Rejected findings are left untouched.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from ..context import RunContext

_CWE = re.compile(r"\bCWE[-_ ]?(\d+)\b", re.IGNORECASE)


def _norm_file(path: str) -> str:
    return path.lstrip("./").replace("\\", "/")


def _weakness(finding: dict[str, Any]) -> str:
    """First CWE id the finding names, else its attack class."""
    for field in ("weakness", "title", "description"):
        m = _CWE.search(str(finding.get(field) or ""))
        if m:
            return f"CWE-{int(m.group(1))}"
    return finding.get("attack_class", "")


def dedup_key(finding: dict[str, Any]) -> str:
    """Stable root-cause key: file + (symbol or line bucket) + weakness."""
    loc = finding.get("location") or {}
    file = _norm_file(loc.get("file", ""))
    symbol = (loc.get("symbol") or "").lower()
    if not symbol:
        line = loc.get("line")
        symbol = f"L{line // 10}" if isinstance(line, int) else "L?"
    raw = f"{file}|{symbol}|{_weakness(finding)}"
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


def _rank(finding: dict[str, Any]) -> tuple:
    """Higher sorts first => becomes canonical. Prefer confirmed, then a
    present patch, then a present PoC."""
    verdict_rank = {"confirmed": 2, "needs_validation": 1}.get(finding.get("verdict"), 0)
    return (verdict_rank, bool(finding.get("patch")), bool(finding.get("poc")))


def run_task(ctx: RunContext, payload: dict[str, Any]) -> dict[str, Any]:
    findings = [f for f in ctx.store.findings(ctx.run_id) if f.get("verdict") != "rejected"]

    clusters: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        clusters.setdefault(dedup_key(f), []).append(f)

    duplicates = 0
    for key, group in clusters.items():
        group.sort(key=_rank, reverse=True)
        canonical = group[0]
        for i, f in enumerate(group):
            f["dedup"] = {"key": key, "canonical": i == 0,
                          "cluster_size": len(group),
                          "canonical_id": canonical.get("id")}
            if i != 0:
                duplicates += 1
            ctx.store.upsert_finding(ctx.run_id, ctx.repo_name, "dedup", f)

    return {"clusters": len(clusters), "findings": len(findings), "duplicates": duplicates}
