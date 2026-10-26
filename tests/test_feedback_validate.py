"""Validate-side feedback: every verdict path records exactly its own lesson kinds.

Each test drives the real validate stage (pass 1, the PoC run in a StubSandbox,
pass 2, the patch gate) on a scripted finding and sweeps ``store.lesson_signals``
so a path that records an extra kind, or the wrong one, fails.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from openplow.context import RunContext
from openplow.db import Store
from openplow.models import FixtureAdapter, ModelAdapter, ModelResponse, Outcome, StubAdapter
from openplow.poc import PocRun
from openplow.sandbox import SandboxResult, StubSandbox
from openplow.stages import validate
from openplow.stages.validate import _unexecuted_kind

CLS = "web-protocol-and-auth"
MARKER = "OPENPLOW_PWNED"


@pytest.fixture
def ctx(tmp_path: Path) -> RunContext:
    repo = tmp_path / "target"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "app.py").write_text("def handler(req):\n    return eval(req)\n")
    out = tmp_path / "out"
    out.mkdir()
    store = Store(tmp_path / "db.sqlite")
    c = RunContext(run_id="run-v", repo=repo, out_dir=out, store=store,
                   finder=StubAdapter(), validator=_verdict("confirmed"),
                   sandbox=StubSandbox(out / "scratch"))
    store.create_run("run-v", "target", "stub")
    return c


def _verdict(v: str) -> FixtureAdapter:
    return FixtureAdapter({"validator_verdict": v}, name=f"fixture-{v}")


class _Retryable(ModelAdapter):
    """A validator whose call failed transiently, so pass 2 raises."""

    name = "retryable"

    def complete(self, system: str, prompt: str, *, max_tokens: int = 4096) -> ModelResponse:
        return ModelResponse(outcome=Outcome.RETRYABLE, text="", error="overloaded")


class _TimeoutSandbox(StubSandbox):
    """Every run hits the wall-clock limit."""

    def run(self, argv: list[str], *, cwd: str | Path | None = None) -> SandboxResult:
        return SandboxResult(124, "", "", timed_out=True)


def _script(body: str) -> dict[str, Any]:
    return {"kind": "script", "content": body, "observed": MARKER}


REPRODUCES = _script(f"print('{MARKER}')\n")


def _finding(fid: str, poc: dict[str, Any] | None, cls: str = CLS, **kw: Any) -> dict[str, Any]:
    f: dict[str, Any] = {
        "id": fid, "verdict": "needs_validation", "title": fid, "attack_class": cls,
        "threat_model": {"attacker": "remote", "boundary": "input -> exec"},
        "location": {"file": "src/app.py", "line": 2, "symbol": "handler"},
    }
    if poc is not None:
        f["poc"] = poc
    f.update(kw)
    return f


def _validate(ctx: RunContext, finding: dict[str, Any]) -> dict[str, Any]:
    ctx.store.upsert_finding(ctx.run_id, ctx.repo_name, "hunt", finding)
    return validate.run_task(ctx, {"finding_id": finding["id"]})


def _signals(ctx: RunContext) -> dict[tuple[str, str], int]:
    return {(r["attack_class"], r["kind"]): r["count"]
            for r in ctx.store.lesson_signals(ctx.run_id)}


# ---- every verdict path ------------------------------------------------

def test_pass1_problem_records_incomplete_finding(ctx):
    out = _validate(ctx, _finding("f1", None))  # no PoC
    assert out["verdict"] == "rejected"
    assert _signals(ctx) == {(CLS, "incomplete_finding"): 1}


def test_tampering_poc_records_poc_tampered(ctx):
    poc = _script(f"open('src/app.py', 'w').write('x = 1\\n')\nprint('{MARKER}')\n")
    out = _validate(ctx, _finding("f2", poc))
    assert out["verdict"] == "rejected"
    assert _signals(ctx) == {(CLS, "poc_tampered"): 1}


def test_non_reproducing_poc_records_poc_not_reproduced(ctx):
    out = _validate(ctx, _finding("f3", _script("import sys\nsys.exit(1)\n")))
    assert out["verdict"] == "rejected"
    assert _signals(ctx) == {(CLS, "poc_not_reproduced"): 1}


def test_timed_out_poc_records_poc_timeout(ctx, tmp_path):
    ctx.sandbox = _TimeoutSandbox(tmp_path / "timeout-scratch")
    out = _validate(ctx, _finding("f4", REPRODUCES))
    assert out["verdict"] == "rejected"
    assert _signals(ctx) == {(CLS, "poc_timeout"): 1}


def test_reproduced_and_confirmed_records_nothing(ctx):
    out = _validate(ctx, _finding("f5", REPRODUCES))
    assert out["verdict"] == "confirmed"
    assert _signals(ctx) == {}


def test_reproduced_but_disproved_records_disproved(ctx):
    ctx.validator = _verdict("rejected")
    out = _validate(ctx, _finding("f6", REPRODUCES))
    assert out["verdict"] == "rejected"
    assert _signals(ctx) == {(CLS, "disproved"): 1}


def test_non_executable_poc_confirmed_records_poc_not_executable(ctx):
    out = _validate(ctx, _finding("f7", {"kind": "input", "content": "eval(1)"}))
    assert out["verdict"] == "confirmed"
    assert _signals(ctx) == {(CLS, "poc_not_executable"): 1}


def test_non_executable_poc_rejected_records_two_signals(ctx):
    ctx.validator = _verdict("rejected")
    out = _validate(ctx, _finding("f8", {"kind": "trace", "content": "a -> b"}))
    assert out["verdict"] == "rejected"
    assert _signals(ctx) == {(CLS, "poc_not_executable"): 1, (CLS, "disproved"): 1}


def test_empty_script_poc_records_incomplete_finding_only(ctx):
    out = _validate(ctx, _finding("f9", {"kind": "script", "content": ""}))
    assert out["verdict"] == "confirmed"
    assert _signals(ctx) == {(CLS, "incomplete_finding"): 1}


def test_retryable_validator_on_non_executable_poc_records_nothing(ctx):
    ctx.validator = _Retryable()
    with pytest.raises(RuntimeError):
        _validate(ctx, _finding("f10", {"kind": "input", "content": "eval(1)"}))
    assert _signals(ctx) == {}


def test_missing_runtime_records_no_poc_not_executable(ctx):
    poc = {"kind": "script", "path": "exploit.unknownext", "content": "boom"}
    out = _validate(ctx, _finding("f11", poc))
    assert out["verdict"] == "confirmed"
    assert _signals(ctx) == {}


def test_unknown_attack_class_records_nothing_and_does_not_raise(ctx):
    out = _validate(ctx, _finding("f12", _script("import sys\nsys.exit(1)\n"), cls="unknown"))
    assert out["verdict"] == "rejected"
    finding = _finding("f13", None)
    del finding["attack_class"]
    assert _validate(ctx, finding)["verdict"] == "rejected"
    assert _signals(ctx) == {}


def test_failed_patch_gate_records_patch_failed_alongside_confirmed(ctx):
    patch = ("--- a/src/app.py\n+++ b/src/app.py\n@@ -1,1 +1,1 @@\n"
             "-def no_such_line():\n+def fixed():\n")
    out = _validate(ctx, _finding("f14", REPRODUCES, patch=patch))
    assert out["verdict"] == "confirmed"
    assert out["fix_verified"] is False
    assert _signals(ctx) == {(CLS, "patch_failed"): 1}


# ---- _unexecuted_kind --------------------------------------------------

@pytest.mark.parametrize("poc,expected", [
    ({"kind": "input", "content": "x"}, "poc_not_executable"),
    ({"kind": "trace", "content": "x"}, "poc_not_executable"),
    ({"kind": "curl", "content": "x"}, "poc_not_executable"),
    ({"content": "x"}, "poc_not_executable"),
    ({"kind": "script", "content": ""}, "incomplete_finding"),
    ({"kind": "test"}, "incomplete_finding"),
    ({"kind": "script", "path": "p.unknownext"}, None),
    ({"kind": "test", "content": "assert True"}, None),
])
def test_unexecuted_kind_when_not_attempted(poc, expected):
    run = PocRun(attempted=False, reason="anything")
    assert _unexecuted_kind({"poc": poc}, run) == expected


def test_unexecuted_kind_none_when_attempted():
    run = PocRun(attempted=True)
    assert _unexecuted_kind({"poc": {"kind": "input"}}, run) is None


def test_unexecuted_kind_ignores_reason_text():
    run = PocRun(attempted=False, reason="runtime 'node' not available")
    assert _unexecuted_kind({"poc": {"kind": "trace"}}, run) == "poc_not_executable"
