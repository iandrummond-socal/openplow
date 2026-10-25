"""Tests for the benchmark harness and the multi-run task-scoping fix."""

from __future__ import annotations

from pathlib import Path

from openplow import benchmark as bm
from openplow.benchmark import ExpectedVuln, TargetSpec, score_target
from openplow.context import RunContext
from openplow.db import Store
from openplow.models import StubAdapter
from openplow.orchestrator import start_run
from openplow.sandbox import StubSandbox

SAMPLE = Path(__file__).resolve().parent.parent / "benchmarks" / "sample" / "benchmark.json"
FIXTURE = Path(__file__).resolve().parent.parent / "benchmarks" / "sample" / "fixture.json"


# ---- matching / scoring -------------------------------------------------

def test_matches_file_regardless_of_class():
    exp = ExpectedVuln(id="v", file="src/app.py", attack_class="web-protocol-and-auth")
    assert bm.matches({"location": {"file": "src/app.py"},
                       "attack_class": "web-protocol-and-auth"}, exp)
    assert not bm.matches({"location": {"file": "src/other.py"},
                           "attack_class": "web-protocol-and-auth"}, exp)
    # the same bug found from another class angle still counts
    assert bm.matches({"location": {"file": "src/app.py"},
                       "attack_class": "client-side"}, exp)


def test_matches_symbol_and_line_range():
    exp = ExpectedVuln(id="v", file="a.py", attack_class="c", symbol="handler",
                       line_range=[1, 10])
    assert bm.matches({"location": {"file": "a.py", "line": 5, "symbol": "handler"},
                       "attack_class": "c"}, exp)
    # symbol mismatch
    assert not bm.matches({"location": {"file": "a.py", "line": 5, "symbol": "other"},
                           "attack_class": "c", "title": "x", "description": "y"}, exp)
    # line out of range
    assert not bm.matches({"location": {"file": "a.py", "line": 50, "symbol": "handler"},
                           "attack_class": "c"}, exp)


def test_score_target_counts():
    spec = TargetSpec(name="t", path="t", expected=[
        ExpectedVuln(id="v1", file="a.py", attack_class="c"),
        ExpectedVuln(id="v2", file="b.py", attack_class="c"),
    ])
    findings = [
        {"location": {"file": "a.py"}, "attack_class": "c", "verdict": "confirmed"},
        {"location": {"file": "z.py"}, "attack_class": "c", "verdict": "rejected"},
    ]
    s = score_target(spec, findings)
    assert s.matched == 1
    assert s.confirmed_matched == 1
    assert s.missed == ["v2"]
    assert s.candidates_total == 2
    assert s.rejected == 1
    assert s.recall == 0.5
    assert s.rejection_rate == 0.5


# ---- regression: two runs in one database both execute ------------------

def test_two_runs_one_store_both_drain(tmp_path):
    """task_id collided globally before the (run_id, task_id) fix, so a second
    run in the same DB got zero tasks."""
    store = Store(tmp_path / "db.sqlite")
    repo = tmp_path / "r"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "a.py").write_text("x = 1\n")

    for rid in ("run-a", "run-b"):
        out = tmp_path / rid
        out.mkdir()
        ctx = RunContext(run_id=rid, repo=repo, out_dir=out, store=store,
                         finder=StubAdapter(), validator=StubAdapter(),
                         sandbox=StubSandbox(out / "scratch"))
        start_run(ctx)
        counts = store.task_counts(rid)
        assert counts.get("done", 0) > 0, f"{rid} ran no tasks"


# ---- end-to-end benchmark with the sample fixture -----------------------

def test_sample_benchmark_full_recall(tmp_path):
    spec = bm.load_spec(SAMPLE)
    report = bm.run_benchmark(
        spec, finder_spec=f"fixture:{FIXTURE}", validator_spec=f"fixture:{FIXTURE}",
        sandbox_kind="stub", out_dir=tmp_path / "out",
    )
    assert report.totals["recall"] == 1.0
    assert report.totals["confirmed_recall"] == 1.0
    assert (tmp_path / "out" / "benchmark-report.md").exists()
    assert (tmp_path / "out" / "benchmark-results.json").exists()


# ---- CVE benchmark: real reproductions, PoC + patch gate ----------------

CVE_SPEC = Path(__file__).resolve().parent.parent / "benchmarks" / "cve" / "benchmark.json"
CVE_FIXTURE = Path(__file__).resolve().parent.parent / "benchmarks" / "cve" / "fixture.json"


def test_cve_benchmark_recall_and_fix_gate(tmp_path):
    spec = bm.load_spec(CVE_SPEC)
    assert len(spec.targets) == 4
    report = bm.run_benchmark(
        spec, finder_spec=f"fixture:{CVE_FIXTURE}", validator_spec=f"fixture:{CVE_FIXTURE}",
        sandbox_kind="stub", out_dir=tmp_path / "out",
    )
    assert report.totals["recall"] == 1.0
    assert report.totals["confirmed_recall"] == 1.0

    # Every confirmed finding's PoC reproduced and its real fix flipped the gate.
    import json
    results = json.loads((tmp_path / "out" / "benchmark-results.json").read_text())
    assert results["totals"]["confirmed_matched"] == 4

    gated = 0
    for fjson in (tmp_path / "out").glob("bench-*/findings.json"):
        for f in json.loads(fjson.read_text()):
            if f.get("verdict") == "confirmed":
                assert (f.get("fix") or {}).get("gate_passed") is True, f["id"]
                gated += 1
    assert gated == 4
