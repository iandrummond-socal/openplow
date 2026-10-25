"""Offline re-scoring of a saved benchmark run. No network, no PoC runs."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from openplow import benchmark as bm
from openplow.cli import main
from openplow.rescore import TargetsChanged, rescore

ROOT = Path(__file__).resolve().parent.parent / "benchmarks"
CVE_SPEC = ROOT / "cve" / "benchmark.json"
CVE_FIXTURE = ROOT / "cve" / "fixture.json"


@pytest.fixture
def cve_run(tmp_path) -> Path:
    out = tmp_path / "run"
    bm.run_benchmark(bm.load_spec(CVE_SPEC), finder_spec=f"fixture:{CVE_FIXTURE}",
                     validator_spec=f"fixture:{CVE_FIXTURE}", sandbox_kind="stub",
                     out_dir=out)
    return out


def test_rescore_reproduces_the_original_totals(cve_run):
    before = json.loads((cve_run / "benchmark-results.json").read_text())["totals"]
    original_md = (cve_run / "benchmark-report.md").read_text()
    after = rescore(cve_run, bm.load_spec(CVE_SPEC)).totals
    for k in ("recall", "confirmed_recall", "rejection_rate", "unmatched_confirmed"):
        assert after[k] == before[k], k
    assert after["fix_verified"] == 4 and after["targets_not_in_run"] == []
    assert (cve_run / "benchmark-report.md").read_text() == original_md   # untouched
    assert "Re-scored offline" in (cve_run / "rescore" / "benchmark-report.md").read_text()


def test_rescore_applies_the_current_dedup_key(cve_run):
    # Simulate an old run whose dedup never folded: two reports of the tar bug
    # from different classes, both marked canonical.
    fj = next(cve_run.glob("bench-cve-2007-4559-tarfile-*/findings.json"))
    findings = json.loads(fj.read_text())
    bug = next(f for f in findings if f.get("verdict") == "confirmed")
    twin = json.loads(json.dumps(bug))
    twin.update(id="twin", attack_class="client-side",
                weakness="CWE-22: Path Traversal", dedup={"canonical": True})
    bug["weakness"] = "CWE-22 (tar slip)"
    findings.append(twin)
    fj.write_text(json.dumps(findings))
    t = rescore(cve_run, bm.load_spec(CVE_SPEC)).totals
    assert t["duplicates_folded"] >= 1
    assert t["unmatched_confirmed"] == 0          # the twin folded into the real bug


def test_rescore_reports_targets_missing_from_the_run(cve_run):
    for d in cve_run.glob("bench-zip-slip-*"):
        (d / "findings.json").unlink()
    t = rescore(cve_run, bm.load_spec(CVE_SPEC)).totals
    assert t["targets_not_in_run"] == ["zip-slip"] and t["expected_total"] == 3


def test_rescore_cli(cve_run, capsys):
    assert main(["rescore", str(cve_run), "--spec", str(CVE_SPEC),
                 "--out", str(cve_run / "r2")]) == 0
    out = capsys.readouterr().out
    assert "recall=100%" in out and "fix_verified=4" in out
    assert (cve_run / "r2" / "benchmark-results.json").exists()


def test_rescore_cli_errors_on_a_dir_without_runs(tmp_path, capsys):
    assert main(["rescore", str(tmp_path), "--spec", str(CVE_SPEC)]) == 2
    assert "no bench-" in capsys.readouterr().err


# ---- re-running the fix gate ---------------------------------------------

def test_benchmark_records_a_hash_of_each_target(cve_run):
    hashes = json.loads((cve_run / "benchmark-results.json").read_text())["totals"][
        "target_hashes"]
    assert set(hashes) == {t.name for t in bm.load_spec(CVE_SPEC).targets}
    assert all(len(h) == 64 for h in hashes.values())


def test_rerun_fix_gate_reproduces_the_recorded_result(cve_run):
    t = rescore(cve_run, bm.load_spec(CVE_SPEC), rerun_fix_gate=True).totals
    assert t["fix_gate_rerun"] and t["fix_gate_run"] == 4
    assert t["fix_gate_changed"] == 0 and t["fix_verified"] == 4
    md = (cve_run / "rescore" / "benchmark-report.md").read_text()
    assert "fix gate was re-run on 4 finding(s)" in md
    assert any((cve_run / "rescore").glob("bench-*/findings.json"))


def test_rerun_fix_gate_skips_findings_without_a_patch(cve_run):
    for fj in cve_run.glob("bench-*/findings.json"):
        findings = json.loads(fj.read_text())
        for f in findings:
            if f.get("verdict") == "confirmed" and f.get("patch"):
                f["patch"] = ""        # no patch: nothing to gate, nothing re-run
        fj.write_text(json.dumps(findings))
    t = rescore(cve_run, bm.load_spec(CVE_SPEC), rerun_fix_gate=True).totals
    assert t["fix_gate_run"] == 0


def test_rerun_fix_gate_flags_a_changed_result(cve_run):
    fj = next(cve_run.glob("bench-cve-2007-4559-tarfile-*/findings.json"))
    findings = json.loads(fj.read_text())
    for f in findings:
        if f.get("verdict") == "confirmed" and f.get("fix"):
            f["fix"]["gate_passed"] = False        # the recorded result was a fail
    fj.write_text(json.dumps(findings))
    t = rescore(cve_run, bm.load_spec(CVE_SPEC), rerun_fix_gate=True).totals
    assert t["fix_gate_changed"] >= 1


def test_rerun_fix_gate_refuses_when_a_target_changed(cve_run, tmp_path):
    spec = bm.load_spec(CVE_SPEC)
    results = json.loads((cve_run / "benchmark-results.json").read_text())
    name = spec.targets[0].name
    results["totals"]["target_hashes"][name] = "0" * 64
    (cve_run / "benchmark-results.json").write_text(json.dumps(results))
    with pytest.raises(TargetsChanged, match="changed since the run"):
        rescore(cve_run, spec, rerun_fix_gate=True)
    assert not (cve_run / "rescore" / "scratch").exists()      # nothing was run


def test_rerun_fix_gate_needs_a_flag_for_runs_without_hashes(cve_run):
    results = json.loads((cve_run / "benchmark-results.json").read_text())
    del results["totals"]["target_hashes"]
    (cve_run / "benchmark-results.json").write_text(json.dumps(results))
    spec = bm.load_spec(CVE_SPEC)
    with pytest.raises(TargetsChanged, match="did not record a hash"):
        rescore(cve_run, spec, rerun_fix_gate=True)
    t = rescore(cve_run, spec, rerun_fix_gate=True, assume_targets_unchanged=True).totals
    assert t["fix_gate_run"] == 4


def test_cli_rerun_fix_gate_reports_a_refusal(cve_run, capsys):
    results = json.loads((cve_run / "benchmark-results.json").read_text())
    results["totals"]["target_hashes"] = {}
    (cve_run / "benchmark-results.json").write_text(json.dumps(results))
    code = main(["rescore", str(cve_run), "--spec", str(CVE_SPEC), "--rerun-fix-gate"])
    assert code == 2 and "did not record a hash" in capsys.readouterr().err
    code = main(["rescore", str(cve_run), "--spec", str(CVE_SPEC), "--rerun-fix-gate",
                 "--assume-targets-unchanged"])
    assert code == 0 and "fix gate re-run on 4" in capsys.readouterr().out
