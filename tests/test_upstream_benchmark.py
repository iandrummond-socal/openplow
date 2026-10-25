"""The upstream CVE benchmark: real pre-fix project source as known-vuln targets.

Runs the fixture benchmark over the two vendored targets. The finder output is
replayed, but each PoC and the fail->pass patch gate run for real against the
vendored source, so this checks that the targets reproduce, that the fixes flip
the gate, and that scoring reaches full recall.

The JWT target imports a crypto library; the suite is skipped where it is
absent (it is in the ``dev`` and ``benchmarks`` extras).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from openplow import benchmark as bm

ROOT = Path(__file__).resolve().parent.parent / "benchmarks" / "upstream"
SPEC = ROOT / "benchmark.json"
FIXTURE = ROOT / "fixture.json"


@pytest.fixture
def report(tmp_path):
    return bm.run_benchmark(
        bm.load_spec(SPEC), finder_spec=f"fixture:{FIXTURE}",
        validator_spec=f"fixture:{FIXTURE}", sandbox_kind="stub", out_dir=tmp_path / "out")


def test_both_upstream_targets_reproduce_and_fix_verifies(report, tmp_path):
    t = report.totals
    assert t["recall"] == 1.0 and t["confirmed_recall"] == 1.0
    assert t["unmatched_confirmed"] == 0

    out = tmp_path / "out"
    confirmed, gate_passed = 0, 0
    for fj in out.glob("bench-*/findings.json"):
        for f in json.loads(fj.read_text()):
            if f.get("verdict") == "confirmed":
                confirmed += 1
                gate_passed += bool((f.get("fix") or {}).get("gate_passed"))
    assert confirmed == 2 and gate_passed == 2


def test_dos_target_is_scored_as_reproduced_not_timed_out(tmp_path):
    # The DoS PoC must detect its own hang and exit 0 with its marker; a plain
    # hang would be a sandbox timeout and score as "did not reproduce".
    bm.run_benchmark(
        bm.load_spec(SPEC), finder_spec=f"fixture:{FIXTURE}",
        validator_spec=f"fixture:{FIXTURE}", sandbox_kind="stub", out_dir=tmp_path / "o")
    dos = next((tmp_path / "o").glob("bench-*zip*/findings.json"))
    finding = next(f for f in json.loads(dos.read_text()) if f["id"] == "ancestry-dos")
    assert finding["verdict"] == "confirmed"
    assert finding["validation"]["poc_demonstrated"] is True


def test_targets_carry_no_project_identifiers():
    # The finder reads the target source and its directory name; neither may name
    # the upstream project, or the finder could recall the advisory.
    banned = ("pyjwt", "jpadilla", "padilla", "zipp", "jaraco", "cve-", "ghsa-")
    for path in (ROOT / "targets").rglob("*.py"):
        text = path.read_text(encoding="utf-8").lower()
        hits = [w for w in banned if w in text]
        assert not hits, f"{path} names the project/advisory: {hits}"
