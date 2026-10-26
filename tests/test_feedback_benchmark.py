"""Benchmark side of the feedback loop: coverage cells, lessons import, the two
training-only signals, and the leakage invariant. Fixture adapters only, no network."""

from __future__ import annotations

import copy
import json
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from openplow import benchmark as bm
from openplow import feedback, pricing
from openplow.context import RunContext
from openplow.db import Store
from openplow.models import build_adapter
from openplow.orchestrator import start_run
from openplow.rescore import rescore
from openplow.sandbox import build_sandbox
from openplow.stages.recon import ATTACK_CLASSES

ROOT = Path(__file__).resolve().parent.parent / "benchmarks"
TRAIN_SPEC = ROOT / "cve-and-decoys.json"
CVE_SPEC = ROOT / "cve" / "benchmark.json"
CVE_FIXTURE = ROOT / "cve" / "fixture.json"
UPSTREAM_FIXTURE = ROOT / "upstream" / "fixture.json"

# A finding whose PoC "reproduces" on any code that has src/auth.py, so the fixture
# validator confirms it on the sqlite-login decoy: a false positive by construction.
_MARKER_FINDING = {
    "id": "marker-finding",
    "verdict": "needs_validation",
    "title": "Marker check",
    "attack_class": "web-protocol-and-auth",
    "severity": "low",
    "weakness": "CWE-000: marker",
    "threat_model": {"attacker": "remote client", "boundary": "request handling"},
    "location": {"file": "src/auth.py", "line": 3, "symbol": "helper"},
    "description": "A finding whose PoC always prints its marker.",
    "poc": {"kind": "script", "content": "print('MARKER_SEEN')\n", "observed": "MARKER_SEEN"},
}


def _merged_fixture(tmp_path: Path) -> dict:
    """The merged fixture Task 5 commits, built here from its two sources."""
    cve = json.loads(CVE_FIXTURE.read_text())
    upstream = json.loads(UPSTREAM_FIXTURE.read_text())
    assert not set(cve["hunts"]) & set(upstream["hunts"])
    return {"validator_verdict": cve["validator_verdict"],
            "hunts": {**cve["hunts"], **upstream["hunts"]}}


def _write(tmp_path: Path, name: str, data: dict) -> str:
    p = tmp_path / name
    p.write_text(json.dumps(data, indent=2))
    return f"fixture:{p}"


def _miss_and_fp_fixture(tmp_path: Path) -> str:
    """The merged fixture with the cmd-injection hunt removed (a known vuln is
    missed) and a marker finding added (confirmed on a decoy)."""
    data = _merged_fixture(tmp_path)
    del data["hunts"]["src/cloud-and-deployment"]
    data["hunts"]["src/web-protocol-and-auth"].append(copy.deepcopy(_MARKER_FINDING))
    return _write(tmp_path, "miss-and-fp.json", data)


def _run(spec_path: Path, fixture: str, out: Path, **kw) -> bm.BenchmarkReport:
    return bm.run_benchmark(bm.load_spec(spec_path), finder_spec=fixture,
                            validator_spec=fixture, sandbox_kind="stub", out_dir=out, **kw)


def _rows(out: Path) -> list[dict]:
    store = Store(out / "benchmark.sqlite")
    try:
        rows = store._conn.execute(
            "SELECT run_id, attack_class, kind, source, count FROM lessons").fetchall()
        return [dict(r) for r in rows]
    finally:
        store.close()


# ---- cells_covered -------------------------------------------------------------

def _f(verdict: str, cell: tuple[str, str] | None, *, canonical: bool | None = None,
       cls: str = "client-side") -> dict:
    f: dict = {"verdict": verdict, "attack_class": cls, "location": {"file": "a.py"}}
    if cell is not None:
        f["provenance"] = {"task_id": f"hunt:{cell[0]}:{cell[1]}"}
    if canonical is not None:
        f["dedup"] = {"canonical": canonical}
    return f


def test_cells_covered_counts_distinct_confirmed_canonical_cells():
    findings = [
        _f("confirmed", ("src", "client-side")),
        _f("confirmed", ("src", "client-side")),                 # same cell again
        _f("confirmed", ("src", "ai-and-llm"), canonical=True),
        _f("confirmed", ("lib", "client-side")),
        _f("rejected", ("web", "client-side")),                  # rejected: ignored
        _f("needs_validation", ("api", "client-side")),          # unvalidated: ignored
        _f("confirmed", ("dup", "client-side"), canonical=False),  # duplicate: ignored
        _f("confirmed", None),                                   # no provenance: nothing
    ]
    s = bm.score_target(bm.TargetSpec(name="t", path="t"), findings)
    assert s.cells_covered == 3
    assert bm._aggregate("x", "f", "v", [s, s]).totals["cells_covered"] == 6


def test_cells_covered_is_zero_on_a_decoy():
    findings = [_f("confirmed", ("src", "client-side")), _f("confirmed", ("lib", "ai-and-llm"))]
    s = bm.score_target(bm.TargetSpec(name="d", path="d", decoy=True), findings)
    assert s.false_positives == 2 and s.cells_covered == 0


def test_benchmark_and_rescore_agree_on_cells_covered(tmp_path):
    out = tmp_path / "run"
    report = _run(CVE_SPEC, f"fixture:{CVE_FIXTURE}", out)
    again = rescore(out, bm.load_spec(CVE_SPEC))
    assert report.totals["cells_covered"] > 0
    assert again.totals["cells_covered"] == report.totals["cells_covered"]
    assert ({s.name: s.cells_covered for s in again.targets}
            == {s.name: s.cells_covered for s in report.targets})
    md = (out / "benchmark-report.md").read_text()
    assert f"- Coverage cells (with a surviving finding): {report.totals['cells_covered']}" in md
    assert "Coverage cells" in (out / "rescore" / "benchmark-report.md").read_text()


# ---- training signals ------------------------------------------------------------

def _assert_training_rows_match_scores(report: bm.BenchmarkReport, out: Path) -> None:
    spec = bm.load_spec(TRAIN_SPEC)
    by_name = {t.name: t for t in spec.targets}
    run_ids = report.totals["run_ids"]
    assert len(run_ids) == len(report.targets) == len(spec.targets)
    rows = [r for r in _rows(out) if r["kind"] in feedback.TRAINING_KINDS]
    assert all(r["source"] == "learned" for r in rows)
    got = {(r["run_id"], r["attack_class"], r["kind"]): r["count"] for r in rows}
    want: dict[tuple[str, str, str], int] = {}
    for run_id, score in zip(run_ids, report.targets, strict=True):
        assert run_id.startswith(f"bench-{score.name}-")
        exp_by_id = {e.id: e for e in by_name[score.name].expected}
        for vuln_id in score.missed:
            key = (run_id, exp_by_id[vuln_id].attack_class, "missed_known")
            want[key] = want.get(key, 0) + 1
        fp = sum(c for (rid, _, k), c in got.items() if rid == run_id and k == "false_positive")
        assert fp == score.false_positives, score.name
    assert {k: v for k, v in got.items() if k[2] == "missed_known"} == want


def test_training_signals_match_the_scores_on_the_merged_fixture(tmp_path):
    out = tmp_path / "train"
    report = _run(TRAIN_SPEC, _write(tmp_path, "merged.json", _merged_fixture(tmp_path)), out,
                  record_training_signals=True)
    _assert_training_rows_match_scores(report, out)


def test_training_signals_land_exactly_on_misses_and_decoy_confirmations(tmp_path):
    out = tmp_path / "train"
    report = _run(TRAIN_SPEC, _miss_and_fp_fixture(tmp_path), out, record_training_signals=True)
    _assert_training_rows_match_scores(report, out)
    # The scenario really exercised both kinds, each on the right target.
    scores = {s.name: s for s in report.targets}
    assert scores["cmd-injection"].missed == ["cmd-injection"]
    assert scores["decoy-sqlite-login"].false_positives == 1
    kinds = {(r["run_id"].rsplit("-", 1)[0], r["attack_class"], r["kind"])
             for r in _rows(out) if r["kind"] in feedback.TRAINING_KINDS}
    assert kinds == {("bench-cmd-injection", "cloud-and-deployment", "missed_known"),
                     ("bench-decoy-sqlite-login", "web-protocol-and-auth", "false_positive")}


def test_plain_runs_never_write_training_kinds(tmp_path):
    fixture = _miss_and_fp_fixture(tmp_path)
    # A benchmark without the flag, on the scenario that has both a miss and a decoy FP.
    out = tmp_path / "plain"
    report = _run(TRAIN_SPEC, fixture, out)
    assert report.totals["false_positives"] == 1 and report.totals["confirmed_recall"] < 1
    rows = _rows(out)
    assert rows, "the plain run still records in-run lessons"
    assert not [r for r in rows if r["kind"] in feedback.TRAINING_KINDS]
    # The `openplow run` path: start_run on the decoy that yields a confirmed finding.
    store = Store(tmp_path / "run.sqlite")
    run_id = f"run-{uuid.uuid4().hex[:12]}"
    run_out = tmp_path / "runs" / run_id
    run_out.mkdir(parents=True)
    adapter = build_adapter(fixture)
    ctx = RunContext(run_id=run_id, repo=(ROOT / "decoys" / "targets" / "sqlite-login").resolve(),
                     out_dir=run_out, store=store, finder=adapter, validator=adapter,
                     sandbox=build_sandbox("stub", run_out / "scratch"))
    start_run(ctx)
    assert any(f["verdict"] == "confirmed" for f in store.findings(run_id))
    assert not [r for r in store.lesson_signals(run_id) if r["kind"] in feedback.TRAINING_KINDS]
    store.close()


# ---- lessons import, budget --------------------------------------------------------

def test_imported_lessons_reach_every_run(tmp_path):
    lessons = {"version": 1, "lessons": [
        {"attack_class": "data-isolation-and-lifecycle", "kind": "poc_not_reproduced",
         "count": 3},
        {"attack_class": "cloud-and-deployment", "kind": "missed_known", "count": 1},
    ]}
    out = tmp_path / "run"
    report = _run(CVE_SPEC, f"fixture:{CVE_FIXTURE}", out, lessons=lessons)
    imported = [r for r in _rows(out) if r["source"] == "imported"]
    for run_id in report.totals["run_ids"]:
        mine = {(r["attack_class"], r["kind"]): r["count"]
                for r in imported if r["run_id"] == run_id}
        assert mine == {("data-isolation-and-lifecycle", "poc_not_reproduced"): 3,
                        ("cloud-and-deployment", "missed_known"): 1}, run_id
    assert len(report.totals["run_ids"]) == len(bm.load_spec(CVE_SPEC).targets)


def test_budget_and_max_cost_together_are_refused(tmp_path):
    with pytest.raises(ValueError, match="max_cost or budget"):
        _run(CVE_SPEC, f"fixture:{CVE_FIXTURE}", tmp_path / "x",
             max_cost=1.0, budget=pricing.Budget(1.0))
    assert not (tmp_path / "x").exists()


def test_shared_budget_sets_the_reported_cap(tmp_path):
    report = _run(CVE_SPEC, f"fixture:{CVE_FIXTURE}", tmp_path / "x",
                  budget=pricing.Budget(0.0))
    assert report.totals["max_cost_usd"] == 0.0 and report.totals["cap_reached"] is True
    assert report.totals["run_ids"] == []


# ---- leakage invariant -------------------------------------------------------------

def test_exported_lessons_never_carry_target_content(tmp_path):
    out = tmp_path / "train"
    report = _run(TRAIN_SPEC, _write(tmp_path, "merged.json", _merged_fixture(tmp_path)), out,
                  record_training_signals=True)
    store = Store(out / "benchmark.sqlite")
    exported = feedback.export_lessons(store, report.totals["run_ids"])
    store.close()
    assert exported["lessons"], "the sweep needs something exported to mean anything"
    feedback.check_lessons(exported)

    secrets: set[str] = set()
    for t in bm.load_spec(TRAIN_SPEC).targets:
        secrets.add(t.name)
        for e in t.expected:
            secrets |= {e.id, e.file} | ({e.symbol} if e.symbol else set())
    for fj in out.glob("bench-*/findings.json"):
        for f in json.loads(fj.read_text()):
            loc = f.get("location") or {}
            secrets |= {f.get("id"), f.get("title"), loc.get("file"), loc.get("symbol")}
    secrets = {s.lower() for s in secrets if s}
    assert {"cve-2007-4559", "src/auth.py", "extract", "login"} <= secrets

    texts = {"exported": json.dumps(exported).lower()}
    probe = Store(tmp_path / "probe.sqlite")
    feedback.import_lessons(probe, "probe", exported)
    for cls in ATTACK_CLASSES:
        ctx = SimpleNamespace(store=probe, run_id="probe", feedback=True)
        texts[cls] = feedback.render(feedback.lessons_for(ctx, cls)).lower()  # type: ignore[arg-type]
    probe.close()
    assert any(texts[c] for c in ATTACK_CLASSES)
    leaks = [(s, where) for s in sorted(secrets) for where, text in texts.items() if s in text]
    assert leaks == []
