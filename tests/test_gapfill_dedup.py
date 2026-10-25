"""Tests for the gapfill and dedup finalization stages."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from openplow.context import RunContext
from openplow.db import Store
from openplow.models import FixtureAdapter, StubAdapter
from openplow.sandbox import StubSandbox
from openplow.stages import dedup, gapfill, hunt


@pytest.fixture
def ctx(tmp_path: Path) -> RunContext:
    repo = tmp_path / "target"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "app.py").write_text("def handler(req):\n    return eval(req)\n")
    out = tmp_path / "out"
    out.mkdir()
    store = Store(tmp_path / "db.sqlite")
    c = RunContext(run_id="run-x", repo=repo, out_dir=out, store=store,
                   finder=StubAdapter(), validator=StubAdapter(),
                   sandbox=StubSandbox(out / "scratch"))
    store.create_run("run-x", "target", "stub")
    return c


def _finding(fid, file="src/app.py", cls="web-protocol-and-auth", symbol="handler",
             verdict="needs_validation", **kw):
    f = {
        "id": fid, "verdict": verdict, "title": fid, "attack_class": cls,
        "threat_model": {"attacker": "remote", "boundary": "input -> exec"},
        "location": {"file": file, "line": 2, "symbol": symbol},
    }
    f.update(kw)
    return f


# ---- dedup --------------------------------------------------------------

def test_dedup_key_stable_and_groups():
    a = _finding("a")
    b = _finding("b")  # same file/class/symbol/boundary => same key
    assert dedup.dedup_key(a) == dedup.dedup_key(b)
    c = _finding("c", file="src/other.py")
    assert dedup.dedup_key(c) != dedup.dedup_key(a)


def test_dedup_marks_one_canonical(ctx: RunContext):
    ctx.store.upsert_finding("run-x", "target", "hunt", _finding("a"))
    ctx.store.upsert_finding("run-x", "target", "hunt", _finding("b"))
    result = dedup.run_task(ctx, {})
    assert result["clusters"] == 1
    assert result["duplicates"] == 1
    canon = [f for f in ctx.store.findings("run-x") if f["dedup"]["canonical"]]
    dups = [f for f in ctx.store.findings("run-x") if not f["dedup"]["canonical"]]
    assert len(canon) == 1 and len(dups) == 1
    assert dups[0]["dedup"]["canonical_id"] == canon[0]["id"]


def test_dedup_prefers_confirmed_as_canonical(ctx: RunContext):
    ctx.store.upsert_finding("run-x", "target", "hunt", _finding("weak"))
    ctx.store.upsert_finding("run-x", "target", "hunt",
                             _finding("strong", verdict="confirmed"))
    dedup.run_task(ctx, {})
    canon = [f for f in ctx.store.findings("run-x") if f["dedup"]["canonical"]]
    assert canon[0]["id"] == "strong"


def test_dedup_ignores_rejected(ctx: RunContext):
    ctx.store.upsert_finding("run-x", "target", "hunt", _finding("r", verdict="rejected"))
    result = dedup.run_task(ctx, {})
    assert result["findings"] == 0


# ---- gapfill ------------------------------------------------------------

def _write_ledger(ctx: RunContext, cells):
    ctx.out_dir.joinpath("coverage-ledger.json").write_text(json.dumps([
        {"area": a, "attack_class": c, "status": "pending"} for a, c in cells
    ]))


def test_gapfill_requeues_only_thin_cells(ctx: RunContext):
    _write_ledger(ctx, [("src", "web-protocol-and-auth"), ("src", "client-side")])
    # web-protocol cell has a surviving finding; client-side is thin.
    f = _finding("f1")
    f["provenance"] = {"run_id": "run-x", "repo": "target", "stage": "hunt",
                       "task_id": "hunt:src:web-protocol-and-auth"}
    ctx.store.upsert_finding("run-x", "target", "hunt", f)

    result = gapfill.run_task(ctx, {"round": 1})
    assert result["enqueued"] == 1  # only client-side
    task = ctx.store.next_pending("run-x", stage="hunt")
    assert task is not None
    assert task.payload["attack_class"] == "client-side"
    assert task.payload["depth"] == 2


def test_gapfill_nothing_when_all_cells_hit(ctx: RunContext):
    _write_ledger(ctx, [("src", "web-protocol-and-auth")])
    f = _finding("f1")
    f["provenance"] = {"task_id": "hunt:src:web-protocol-and-auth"}
    ctx.store.upsert_finding("run-x", "target", "hunt", f)
    assert gapfill.run_task(ctx, {"round": 1})["enqueued"] == 0


# ---- re-hunt does not reset an already-stored finding -------------------

def test_rehunt_skips_existing_finding_id(ctx: RunContext):
    # Store a finding, already rejected by validation.
    ctx.store.upsert_finding("run-x", "target", "hunt", _finding("dup", verdict="rejected"))
    ctx.out_dir.joinpath("architecture.md").write_text("# arch\n")

    # A hunter that re-emits the same id must not overwrite it back to open.
    fixture = {"hunts": {"src/web-protocol-and-auth": [_finding("dup")]}}
    ctx.finder = FixtureAdapter(fixture)
    result = hunt.run_task(ctx, {"area": "src", "attack_class": "web-protocol-and-auth"})
    assert result["skipped"] == 1
    assert result["findings"] == 0
    stored = [f for f in ctx.store.findings("run-x") if f["id"] == "dup"]
    assert stored[0]["verdict"] == "rejected"  # preserved


def test_dedup_folds_same_cwe_across_classes_and_boundaries():
    a = _finding("a", cls="client-side", weakness="CWE-22: Path Traversal")
    a["threat_model"]["boundary"] = "archive -> host filesystem"
    b = _finding("b", cls="cloud-and-deployment", weakness="CWE-22 (Zip Slip) / CWE-59")
    b["threat_model"]["boundary"] = "untrusted entry names escape dest"
    assert dedup.dedup_key(a) == dedup.dedup_key(b)


def test_dedup_keeps_different_cwe_in_same_function_apart():
    traversal = _finding("t", weakness="CWE-22 Path Traversal")
    bomb = _finding("z", weakness="CWE-409: Improper Handling of Highly Compressed Data")
    assert dedup.dedup_key(traversal) != dedup.dedup_key(bomb)


def test_dedup_falls_back_to_title_then_class():
    by_title = _finding("t", title="SQL injection (cwe-89) in login")
    assert dedup.dedup_key(by_title) == dedup.dedup_key(_finding("w", weakness="CWE-89"))
    assert dedup.dedup_key(_finding("x", cls="c1")) != dedup.dedup_key(_finding("y", cls="c2"))
