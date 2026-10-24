"""Benchmark harness.

No labeled set of *all* bugs exists, so recall against every bug is unknowable.
What a benchmark *can* measure is whether OpenPlow finds the bugs we planted or
know about, and how noisy it is getting there. Point it at a set of targets,
each with a manifest of known vulnerabilities, and it runs the full pipeline and
scores the findings.

Metrics per target and in aggregate:

* **recall** — known vulns matched by a finding / known vulns
* **confirmed recall** — known vulns matched by a *confirmed* finding / known vulns
* **validation rejection rate** — rejected findings / all candidate findings
  (Cloudflare's north-star; theirs fell from 40% to 11% as recon improved)
* **unmatched confirmed** — confirmed findings matching no known vuln (either a
  false positive or a genuinely new bug; a benchmark cannot tell which)

A finding matches a known vuln when they share the file and attack class, and —
when the manifest gives one — the symbol or a line within the given range.

Spec format (JSON)::

    {
      "name": "openplow-sample",
      "targets": [
        {"name": "vuln-eval", "path": "targets/vuln-eval",
         "expected": [
           {"id": "eval-rce", "file": "src/app.py",
            "attack_class": "web-protocol-and-auth",
            "symbol": "handler", "line_range": [1, 5]}
         ]}
      ]
    }

Paths in the spec are relative to the spec file's directory.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .context import RunContext
from .db import Store
from .models import build_adapter
from .orchestrator import start_run
from .sandbox import build_sandbox


@dataclass
class ExpectedVuln:
    id: str
    file: str
    attack_class: str
    symbol: str | None = None
    line_range: list[int] | None = None


@dataclass
class TargetSpec:
    name: str
    path: str
    expected: list[ExpectedVuln] = field(default_factory=list)


@dataclass
class BenchmarkSpec:
    name: str
    base_dir: Path
    targets: list[TargetSpec]


def load_spec(path: str | Path) -> BenchmarkSpec:
    p = Path(path).resolve()
    raw = json.loads(p.read_text(encoding="utf-8"))
    targets = [
        TargetSpec(
            name=t["name"], path=t["path"],
            expected=[ExpectedVuln(**e) for e in t.get("expected", [])],
        )
        for t in raw.get("targets", [])
    ]
    return BenchmarkSpec(name=raw.get("name", p.stem), base_dir=p.parent, targets=targets)


# ---- scoring ------------------------------------------------------------

def _norm(path: str) -> str:
    return path.lstrip("./").replace("\\", "/")


def matches(finding: dict[str, Any], exp: ExpectedVuln) -> bool:
    loc = finding.get("location") or {}
    if _norm(loc.get("file", "")) != _norm(exp.file):
        return False
    if finding.get("attack_class") != exp.attack_class:
        return False
    if exp.symbol:
        hay = f"{loc.get('symbol', '')} {finding.get('title', '')} {finding.get('description', '')}"
        if exp.symbol.lower() not in hay.lower():
            return False
    if exp.line_range:
        line = loc.get("line")
        lo, hi = exp.line_range[0], exp.line_range[-1]
        if line is not None and not (lo <= line <= hi):
            return False
    return True


@dataclass
class TargetScore:
    name: str
    expected_total: int
    matched: int
    confirmed_matched: int
    missed: list[str]
    candidates_total: int
    rejected: int
    unmatched_confirmed: int
    recall: float
    confirmed_recall: float
    rejection_rate: float


def _is_duplicate(f: dict[str, Any]) -> bool:
    d = f.get("dedup")
    return bool(d) and not d.get("canonical", True)


def score_target(spec: TargetSpec, findings: list[dict[str, Any]]) -> TargetScore:
    # Fold duplicates so a cluster counts once.
    findings = [f for f in findings if not _is_duplicate(f)]
    confirmed = [f for f in findings if f.get("verdict") == "confirmed"]
    non_rejected = [f for f in findings if f.get("verdict") != "rejected"]
    rejected = [f for f in findings if f.get("verdict") == "rejected"]

    matched_ids: set[str] = set()
    confirmed_ids: set[str] = set()
    matched_findings: set[int] = set()
    for exp in spec.expected:
        for i, f in enumerate(non_rejected):
            if matches(f, exp):
                matched_ids.add(exp.id)
                matched_findings.add(id(f))
                if f in confirmed:
                    confirmed_ids.add(exp.id)
                break

    expected_total = len(spec.expected)
    unmatched_confirmed = sum(1 for f in confirmed if id(f) not in matched_findings)
    candidates = len(findings)

    def _ratio(n: int, d: int) -> float:
        return round(n / d, 3) if d else 0.0

    return TargetScore(
        name=spec.name,
        expected_total=expected_total,
        matched=len(matched_ids),
        confirmed_matched=len(confirmed_ids),
        missed=[e.id for e in spec.expected if e.id not in matched_ids],
        candidates_total=candidates,
        rejected=len(rejected),
        unmatched_confirmed=unmatched_confirmed,
        recall=_ratio(len(matched_ids), expected_total),
        confirmed_recall=_ratio(len(confirmed_ids), expected_total),
        rejection_rate=_ratio(len(rejected), candidates),
    )


@dataclass
class BenchmarkReport:
    name: str
    finder: str
    validator: str
    targets: list[TargetScore]
    totals: dict[str, Any]


def _aggregate(name: str, finder: str, validator: str,
               scores: list[TargetScore]) -> BenchmarkReport:
    exp = sum(s.expected_total for s in scores)
    matched = sum(s.matched for s in scores)
    confirmed = sum(s.confirmed_matched for s in scores)
    cand = sum(s.candidates_total for s in scores)
    rej = sum(s.rejected for s in scores)
    unmatched = sum(s.unmatched_confirmed for s in scores)

    def _ratio(n: int, d: int) -> float:
        return round(n / d, 3) if d else 0.0

    totals = {
        "expected_total": exp, "matched": matched, "confirmed_matched": confirmed,
        "candidates_total": cand, "rejected": rej, "unmatched_confirmed": unmatched,
        "recall": _ratio(matched, exp), "confirmed_recall": _ratio(confirmed, exp),
        "rejection_rate": _ratio(rej, cand),
    }
    return BenchmarkReport(name=name, finder=finder, validator=validator,
                           targets=scores, totals=totals)


# ---- running ------------------------------------------------------------

def run_benchmark(spec: BenchmarkSpec, *, finder_spec: str, validator_spec: str | None,
                  sandbox_kind: str, out_dir: Path) -> BenchmarkReport:
    out_dir.mkdir(parents=True, exist_ok=True)
    finder = build_adapter(finder_spec)
    validator = build_adapter(validator_spec or finder_spec)

    scores: list[TargetScore] = []
    for target in spec.targets:
        repo = (spec.base_dir / target.path).resolve()
        run_id = f"bench-{target.name}-{uuid.uuid4().hex[:8]}"
        target_out = out_dir / run_id
        target_out.mkdir(parents=True, exist_ok=True)
        store = Store(out_dir / "benchmark.sqlite")
        ctx = RunContext(run_id=run_id, repo=repo, out_dir=target_out, store=store,
                         finder=finder, validator=validator,
                         sandbox=build_sandbox(sandbox_kind, target_out / "scratch"))
        start_run(ctx)
        findings = store.findings(run_id)
        scores.append(score_target(target, findings))
        store.close()

    report = _aggregate(spec.name, finder.name, validator.name, scores)
    _write_report(report, out_dir)
    return report


def _write_report(report: BenchmarkReport, out_dir: Path) -> None:
    (out_dir / "benchmark-results.json").write_text(
        json.dumps({
            "name": report.name, "finder": report.finder, "validator": report.validator,
            "totals": report.totals, "targets": [asdict(s) for s in report.targets],
        }, indent=2) + "\n")

    t = report.totals
    lines = [
        f"# Benchmark — {report.name}",
        "",
        f"- Finder: `{report.finder}`  ·  Validator: `{report.validator}`",
        "",
        "## Totals",
        "",
        f"- Known vulns: {t['expected_total']}",
        f"- Recall: **{t['recall']:.0%}** ({t['matched']}/{t['expected_total']})",
        (f"- Confirmed recall: **{t['confirmed_recall']:.0%}** "
         f"({t['confirmed_matched']}/{t['expected_total']})"),
        (f"- Validation rejection rate: {t['rejection_rate']:.0%} "
         f"({t['rejected']}/{t['candidates_total']})"),
        f"- Unmatched confirmed (possible FP or new bug): {t['unmatched_confirmed']}",
        "",
        "## Per target",
        "",
        "| Target | Known | Recall | Confirmed | Rejection | Unmatched |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for s in report.targets:
        lines.append(
            f"| {s.name} | {s.expected_total} | {s.recall:.0%} | "
            f"{s.confirmed_recall:.0%} | {s.rejection_rate:.0%} | {s.unmatched_confirmed} |")
        if s.missed:
            lines.append(f"| ↳ missed: {', '.join(s.missed)} | | | | | |")
    (out_dir / "benchmark-report.md").write_text("\n".join(lines) + "\n")
