"""End-to-end and unit tests for the M1 scaffold, using the stub adapter."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from openplow.context import RunContext
from openplow.db import Store
from openplow.models import Outcome, StubAdapter, build_adapter, classify_body
from openplow.orchestrator import start_run
from openplow.sandbox import StubSandbox, build_sandbox
from openplow.stages import validate


@pytest.fixture
def target_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "target"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "app.py").write_text("def handler(req):\n    return req\n")
    (repo / "src" / "auth.js").write_text("function login(u){return u;}\n")
    return repo


@pytest.fixture
def ctx(tmp_path: Path, target_repo: Path) -> RunContext:
    store = Store(tmp_path / "db.sqlite")
    out = tmp_path / "out"
    out.mkdir()
    return RunContext(
        run_id="run-test", repo=target_repo, out_dir=out, store=store,
        finder=StubAdapter(), validator=StubAdapter(),
        sandbox=StubSandbox(out / "scratch"),
    )


def test_full_run_produces_artifacts(ctx: RunContext):
    summary = start_run(ctx)
    assert summary.failed == 0
    assert summary.processed > 0

    for name in ("architecture.md", "coverage-ledger.json", "findings.json",
                 "REPORT.md", "openplow.sarif"):
        assert (ctx.out_dir / name).exists(), f"missing {name}"

    ledger = json.loads((ctx.out_dir / "coverage-ledger.json").read_text())
    # two areas (src is the only subdir; files are under src/) x 10 classes
    assert len(ledger) >= 10
    assert all(cell["status"] == "pending" for cell in ledger)

    sarif = json.loads((ctx.out_dir / "openplow.sarif").read_text())
    assert sarif["version"] == "2.1.0"


def test_run_is_resumable(ctx: RunContext):
    start_run(ctx)
    counts = ctx.store.task_counts("run-test")
    assert counts.get("done", 0) > 0
    # Resuming a completed run is a no-op that still succeeds.
    summary = start_run(ctx, resume=True)
    assert summary.failed == 0


def test_tasks_dedup(ctx: RunContext):
    assert ctx.store.add_task("t1", "run-test", "repo", "hunt", {"area": "a"}) is True
    assert ctx.store.add_task("t1", "run-test", "repo", "hunt", {"area": "a"}) is False


def test_classify_body_detects_transient_in_200():
    assert classify_body("Overloaded, please try again") is Outcome.RETRYABLE
    assert classify_body("a real, substantive finding body " * 20) is Outcome.OK


def test_build_adapter():
    assert build_adapter("stub").name == "stub"
    a = build_adapter("anthropic:claude-x")
    assert a.name == "anthropic:claude-x"
    with pytest.raises(ValueError):
        build_adapter("nope")


def test_validator_rejects_finding_without_poc(ctx: RunContext):
    finding = {
        "id": "f1", "verdict": "needs_validation", "title": "x",
        "attack_class": "web-protocol-and-auth",
        "threat_model": {"attacker": "remote", "boundary": "auth"},
        "location": {"file": "src/app.py"},
        # no poc
    }
    ctx.store.create_run("run-test", "target", "stub")
    ctx.store.upsert_finding("run-test", "target", "hunt", finding)
    result = validate.run_task(ctx, {"finding_id": "f1"})
    assert result["verdict"] == "rejected"
    assert any("proof of concept" in r for r in result["reasons"])


def test_validator_rejects_missing_file(ctx: RunContext):
    finding = {
        "id": "f2", "verdict": "needs_validation", "title": "x",
        "attack_class": "web-protocol-and-auth",
        "threat_model": {"attacker": "remote", "boundary": "auth"},
        "location": {"file": "src/does-not-exist.py"},
        "poc": {"kind": "test", "content": "assert False"},
    }
    ctx.store.create_run("run-test", "target", "stub")
    ctx.store.upsert_finding("run-test", "target", "hunt", finding)
    result = validate.run_task(ctx, {"finding_id": "f2"})
    assert result["verdict"] == "rejected"


def test_sandbox_runs_in_clean_env(tmp_path: Path):
    sb = build_sandbox("stub", tmp_path / "scratch", timeout=5)
    res = sb.run(["python3", "-c", "import os; print(os.environ.get('SECRET', 'none'))"])
    assert res.returncode == 0
    assert "none" in res.stdout
