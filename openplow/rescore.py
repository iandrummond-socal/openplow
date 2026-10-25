"""Re-score a finished benchmark run offline.

A benchmark run leaves its findings on disk (``<out>/bench-<target>-<id>/
findings.json``) and its token usage in ``<out>/benchmark.sqlite``. Re-scoring
reads those back and applies the *current* dedup key and scoring rules, so a
change to either can be measured against old runs at no cost: no model is
called and no PoC or patch is executed. Verdicts, PoC results and fix-gate
results are taken as recorded.

With ``rerun_fix_gate`` the fix gate (reproduce, patch, must not reproduce) is
run again for every canonical confirmed finding that ships a patch. That runs
code, so it is opt-in, and it is only valid when the target source is the one the
run used. A run records a hash of each target; the re-run refuses when it differs,
and refuses when the run recorded none, unless the caller says the targets are
unchanged. No model is called either way.

The new report goes to a separate directory (``<out>/rescore`` by default); the
original run's report is never overwritten.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from . import poc as poc_mod
from . import pricing
from .benchmark import BenchmarkReport, BenchmarkSpec, _aggregate, _write_report, score_target
from .sandbox import build_sandbox
from .stages.dedup import _rank, dedup_key

_RUN_DIR = re.compile(r"^bench-(?P<target>.+)-(?P<id>[0-9a-f]{8})$")


def _target_runs(run_dir: Path, spec: BenchmarkSpec) -> dict[str, Path]:
    """Map each spec target to its run directory (the newest, if several)."""
    names = {t.name for t in spec.targets}
    found: dict[str, Path] = {}
    for d in sorted(run_dir.glob("bench-*"), key=lambda p: p.stat().st_mtime):
        m = _RUN_DIR.match(d.name)
        if m and m.group("target") in names and (d / "findings.json").exists():
            found[m.group("target")] = d
    return found


def redup(findings: list[dict[str, Any]]) -> int:
    """Re-mark duplicates with the current dedup key, as the dedup stage would.
    Rejected findings are left unclustered. Returns the number of duplicates."""
    clusters: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        f.pop("dedup", None)
        if f.get("verdict") != "rejected":
            clusters.setdefault(dedup_key(f), []).append(f)
    duplicates = 0
    for key, group in clusters.items():
        group.sort(key=_rank, reverse=True)
        for i, f in enumerate(group):
            f["dedup"] = {"key": key, "canonical": i == 0, "cluster_size": len(group),
                          "canonical_id": group[0].get("id")}
            duplicates += i != 0
    return duplicates


def _run_cost(db: Path, run_ids: list[str]) -> tuple[float, bool]:
    if not db.exists() or not run_ids:
        return 0.0, True
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        rows = con.execute(
            "SELECT model, SUM(input_tokens), SUM(output_tokens), SUM(cache_read), "
            f"SUM(cache_creation) FROM usage WHERE run_id IN ({','.join('?' * len(run_ids))}) "
            "GROUP BY model", run_ids).fetchall()
    finally:
        con.close()
    total, priced = 0.0, True
    for model, i, o, cr, cc in rows:
        c = pricing.estimate_cost(model, pricing.Usage(i or 0, o or 0, cr or 0, cc or 0))
        if c is None:
            priced = False
        else:
            total += c
    return total, priced


class TargetsChanged(ValueError):
    """The target source is not the one the run used, or cannot be shown to be."""


def _check_targets(spec: BenchmarkSpec, runs: dict[str, Path], recorded: dict[str, str],
                   assume_unchanged: bool) -> None:
    for target in spec.targets:
        if target.name not in runs:
            continue
        digest = poc_mod.tree_digest((spec.base_dir / target.path).resolve())
        if target.name in recorded:
            if recorded[target.name] != digest:
                raise TargetsChanged(
                    f"target {target.name!r} has changed since the run; its fix gate "
                    "cannot be re-run against different source")
        elif not assume_unchanged:
            raise TargetsChanged(
                f"the run did not record a hash for target {target.name!r} (it predates "
                "this check); pass --assume-targets-unchanged if you know it is unchanged")


def _rerun_gate(sandbox, repo: Path, findings: list[dict[str, Any]],
                scratch: Path) -> tuple[int, int]:
    """Re-run the fix gate on canonical confirmed findings that ship a patch.
    Updates each finding's ``fix`` in place. Returns (gates run, results changed)."""
    ran = changed = 0
    for f in findings:
        if (f.get("verdict") != "confirmed" or not (f.get("dedup") or {}).get("canonical")
                or not f.get("patch")):
            continue
        gate = poc_mod.run_patch_gate(sandbox, repo, f, scratch / str(f.get("id", ran)))
        old = (f.get("fix") or {}).get("gate_passed")
        f["fix"] = {
            "gate_passed": gate.passed, "reproduced_before": gate.reproduced_before,
            "patch_applied": gate.patch_applied, "reproduced_after": gate.reproduced_after,
            "reason": gate.reason,
        }
        ran += 1
        changed += old != gate.passed
    return ran, changed


def rescore(run_dir: Path, spec: BenchmarkSpec, out_dir: Path | None = None, *,
            rerun_fix_gate: bool = False, sandbox_kind: str = "stub",
            assume_targets_unchanged: bool = False) -> BenchmarkReport:
    """Re-score the run in ``run_dir`` against ``spec``; write the report to
    ``out_dir`` (default ``run_dir/rescore``) and return it. See the module
    docstring for ``rerun_fix_gate``."""
    run_dir = Path(run_dir).resolve()
    out_dir = Path(out_dir) if out_dir else run_dir / "rescore"
    out_dir.mkdir(parents=True, exist_ok=True)

    runs = _target_runs(run_dir, spec)
    if not runs:
        raise FileNotFoundError(f"no bench-<target>-<id>/findings.json for this spec in {run_dir}")

    original = run_dir / "benchmark-results.json"
    meta = json.loads(original.read_text(encoding="utf-8")) if original.exists() else {}
    if rerun_fix_gate:  # check every target before running any code
        _check_targets(spec, runs, (meta.get("totals") or {}).get("target_hashes") or {},
                       assume_targets_unchanged)

    scores, missing, duplicates, fix_verified = [], [], 0, 0
    gates_run = gates_changed = 0
    for target in spec.targets:
        d = runs.get(target.name)
        if d is None:
            missing.append(target.name)
            continue
        findings = json.loads((d / "findings.json").read_text(encoding="utf-8"))
        duplicates += redup(findings)
        if rerun_fix_gate:
            ran, diff = _rerun_gate(
                build_sandbox(sandbox_kind, out_dir / "scratch" / target.name),
                (spec.base_dir / target.path).resolve(), findings,
                out_dir / "scratch" / target.name)
            gates_run += ran
            gates_changed += diff
            (out_dir / d.name).mkdir(parents=True, exist_ok=True)
            (out_dir / d.name / "findings.json").write_text(
                json.dumps(findings, indent=2) + "\n", encoding="utf-8")
        fix_verified += sum(
            1 for f in findings
            if f.get("verdict") == "confirmed" and (f.get("dedup") or {}).get("canonical")
            and (f.get("fix") or {}).get("gate_passed"))
        scores.append(score_target(target, findings))

    report = _aggregate(spec.name, meta.get("finder", "?"), meta.get("validator", "?"), scores)
    cost, priced = _run_cost(run_dir / "benchmark.sqlite", [d.name for d in runs.values()])
    report.totals.update({
        "estimated_cost_usd": round(cost, 4), "cost_fully_priced": priced,
        "duplicates_folded": duplicates, "fix_verified": fix_verified,
        "rescored_from": str(run_dir), "targets_not_in_run": missing,
        "fix_gate_rerun": rerun_fix_gate, "fix_gate_run": gates_run,
        "fix_gate_changed": gates_changed,
    })
    _write_report(report, out_dir)
    _annotate(out_dir / "benchmark-report.md", report.totals)
    return report


def _annotate(md: Path, t: dict[str, Any]) -> None:
    """Say in the report that it was re-scored, from what, and what it adds."""
    lines = md.read_text(encoding="utf-8").splitlines()
    if t.get("fix_gate_rerun"):
        how = ("No model was called. The fix gate was re-run on "
               f"{t['fix_gate_run']} finding(s) ({t['fix_gate_changed']} changed result); "
               "other verdicts are as recorded.")
    else:
        how = ("No model or PoC was run; verdicts and fix-gate results are as recorded.")
    note = [
        "",
        (f"> Re-scored {'' if t.get('fix_gate_rerun') else 'offline '}from "
         f"`{t['rescored_from']}` with the current dedup and scoring rules. {how}"),
        "",
        f"- Duplicates folded: {t['duplicates_folded']}",
        f"- Fix verified (canonical confirmed findings): {t['fix_verified']}",
    ]
    if t["targets_not_in_run"]:
        note.append(f"- Not in this run (not scored): {', '.join(t['targets_not_in_run'])}")
    md.write_text("\n".join(lines[:1] + note + lines[1:]) + "\n", encoding="utf-8")
