"""Decoy targets: code shaped like the CVE targets but with no bug. Anything
confirmed on a decoy is a false positive. No network."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from openplow import benchmark as bm

ROOT = Path(__file__).resolve().parent.parent / "benchmarks"
DECOY_SPEC = ROOT / "decoys" / "benchmark.json"
DECOY_FIXTURE = ROOT / "decoys" / "fixture.json"


def test_decoy_suite_is_clean_and_rejects_by_running_the_exploit(tmp_path):
    spec = bm.load_spec(DECOY_SPEC)
    assert len(spec.targets) == 4 and all(t.decoy for t in spec.targets)
    report = bm.run_benchmark(spec, finder_spec=f"fixture:{DECOY_FIXTURE}",
                              validator_spec=f"fixture:{DECOY_FIXTURE}",
                              sandbox_kind="stub", out_dir=tmp_path)
    t = report.totals
    assert t["decoy_targets"] == 4 and t["decoys_clean"] == 4 and t["false_positives"] == 0
    # The fixture validator always says "confirmed", so each decoy's own exploit
    # claim must have been rejected because its PoC actually failed to reproduce.
    own = {"decoy-tar-traversal", "decoy-zip-slip", "decoy-sqli", "decoy-cmd-injection"}
    seen = set()
    for f in tmp_path.glob("bench-*/findings.json"):
        for x in json.loads(f.read_text()):
            notes = (x.get("validation") or {}).get("notes", "")
            if "does not exist" in notes:
                continue                     # another target's claim; file absent here
            assert x["verdict"] == "rejected" and notes.startswith("poc-execution"), x["id"]
            seen.add(x["id"])
    assert seen == own
    assert "false positives (confirmed on a decoy): **0**" in (
        tmp_path / "benchmark-report.md").read_text()


# The decoy exploits must be real: each one breaks the matching vulnerable target.
@pytest.mark.parametrize("finding_id,cve_target", [
    ("decoy-tar-traversal", "tar-unpack"),
    ("decoy-zip-slip", "zip-unpack"),
    ("decoy-cmd-injection", "host-ping"),
])
def test_decoy_exploit_breaks_the_vulnerable_target(tmp_path, finding_id, cve_target):
    hunts = json.loads(DECOY_FIXTURE.read_text())["hunts"]
    poc = next(f["poc"] for fs in hunts.values() for f in fs if f["id"] == finding_id)
    target = tmp_path / "t"
    shutil.copytree(ROOT / "cve" / "targets" / cve_target, target)
    (target / "poc.py").write_text(poc["content"])
    proc = subprocess.run([sys.executable, "-I", "poc.py"], cwd=target,
                          capture_output=True, text=True, timeout=60, check=False)
    assert proc.returncode == 0 and poc["observed"] in proc.stdout, proc.stderr


def test_confirmed_finding_on_a_decoy_is_a_false_positive():
    spec = bm.TargetSpec(name="d", path="d", decoy=True)
    s = bm.score_target(spec, [{"verdict": "confirmed", "location": {"file": "a.py"}},
                               {"verdict": "rejected", "location": {"file": "a.py"}}])
    assert s.false_positives == 1 and s.unmatched_confirmed == 0
    report = bm._aggregate("x", "f", "v", [s])
    assert report.totals["false_positives"] == 1 and report.totals["decoys_clean"] == 0


def test_decoy_with_expected_vulns_is_rejected(tmp_path):
    p = tmp_path / "spec.json"
    p.write_text(json.dumps({"targets": [{"name": "d", "path": "d", "decoy": True,
                                          "expected": [{"id": "x", "file": "a.py",
                                                        "attack_class": "c"}]}]}))
    with pytest.raises(ValueError):
        bm.load_spec(p)


def test_combined_spec_loads_cve_and_decoys():
    spec = bm.load_spec(ROOT / "cve-and-decoys.json")
    assert sum(t.decoy for t in spec.targets) == 4 and len(spec.targets) == 8
    for t in spec.targets:
        assert (spec.base_dir / t.path).is_dir(), t.path
