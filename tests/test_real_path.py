"""Tests for the real (non-stub) hunt/validate path, driven by fake adapters
that return canned model text. No network, no API key."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from openplow import findings as fmod
from openplow import skill_loader
from openplow.context import RunContext
from openplow.db import Store
from openplow.models import ModelAdapter, ModelResponse, Outcome
from openplow.sandbox import StubSandbox
from openplow.stages import hunt, validate


class FakeAdapter(ModelAdapter):
    """Returns a fixed response, recording the last prompt it saw."""

    def __init__(self, text: str, name: str = "fake", outcome: Outcome = Outcome.OK):
        self.name = name
        self._text = text
        self._outcome = outcome
        self.last_prompt: str | None = None

    def complete(self, system, prompt, *, max_tokens=4096):
        self.last_prompt = prompt
        return ModelResponse(outcome=self._outcome, text=self._text)


@pytest.fixture
def target_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "target"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "app.py").write_text("def handler(req):\n    return eval(req)\n")
    return repo


def _ctx(tmp_path, repo, finder, validator):
    store = Store(tmp_path / "db.sqlite")
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    (out / "architecture.md").write_text("# Architecture\n")
    ctx = RunContext(run_id="run-real", repo=repo, out_dir=out, store=store,
                     finder=finder, validator=validator,
                     sandbox=StubSandbox(out / "scratch"))
    ctx.store.create_run("run-real", repo.name, finder.name)
    return ctx


# ---- findings parsing ---------------------------------------------------

def test_extract_json_from_fence():
    text = 'blah\n```json\n[{"id": "a"}]\n```\ntrailer'
    assert fmod.extract_json(text) == [{"id": "a"}]


def test_extract_json_bare_array():
    assert fmod.extract_json('[{"id": "a"}, {"id": "b"}]') == [{"id": "a"}, {"id": "b"}]


def test_extract_json_findings_wrapper():
    assert fmod.extract_json('{"findings": [{"id": "a"}]}') == [{"id": "a"}]


def test_extract_json_garbage_returns_empty():
    assert fmod.extract_json("no json here at all") == []


def test_validate_finding_catches_missing_fields():
    problems = fmod.validate_finding({"id": "x"})
    assert problems  # missing verdict, title, threat_model, etc.


def test_validate_finding_accepts_complete():
    good = {
        "id": "x", "verdict": "needs_validation", "title": "t",
        "attack_class": "web-protocol-and-auth",
        "threat_model": {"attacker": "remote", "boundary": "auth"},
        "location": {"file": "src/app.py"},
    }
    assert fmod.validate_finding(good) == []


def test_validate_finding_accepts_the_validators_poc_fields():
    # The validate stage records the PoC run beside the verdict; the schema must
    # name every key it writes.
    finding = {
        "id": "x", "verdict": "confirmed", "title": "t",
        "attack_class": "web-protocol-and-auth",
        "threat_model": {"attacker": "remote", "boundary": "auth"},
        "location": {"file": "src/app.py"},
        "validation": {
            "checked_by": "m", "served_by": "m", "disproof_attempted": True, "notes": "n",
            "poc_attempted": True, "poc_demonstrated": True, "poc_reason": "",
            "poc_enforced": {"seccomp": True, "memory_cap": False},
        },
    }
    assert fmod.validate_finding(finding) == []


# ---- skill loader -------------------------------------------------------

def test_skill_is_vendored():
    assert skill_loader.is_vendored(), "vendored skill missing under skills/security-audit"
    assert skill_loader.load_class_prompt("web-protocol-and-auth")
    assert skill_loader.load_class_prompt("no-such-class") is None


# ---- hunt with a model that returns a finding ---------------------------

def _finding_json() -> str:
    finding = {
        "id": "sqli-1", "verdict": "needs_validation", "title": "eval on request input",
        "attack_class": "web-protocol-and-auth",
        "threat_model": {"attacker": "remote unauthenticated", "boundary": "input -> code exec"},
        "location": {"file": "src/app.py", "line": 2, "symbol": "handler"},
        "description": "handler passes untrusted input to eval",
        "poc": {"kind": "input", "content": "__import__('os').system('id')", "observed": "RCE"},
        "patch": "- return eval(req)\n+ return int(req)",
    }
    return "Found one:\n```json\n[" + json.dumps(finding) + "]\n```"


def test_hunt_files_valid_finding(tmp_path, target_repo):
    finder = FakeAdapter(_finding_json(), name="finder-model")
    ctx = _ctx(tmp_path, target_repo, finder, FakeAdapter("", name="validator-model"))
    result = hunt.run_task(ctx, {"area": "src", "attack_class": "web-protocol-and-auth"})
    assert result["findings"] == 1
    assert result["dropped"] == 0
    stored = ctx.store.findings("run-real")
    assert stored[0]["id"] == "sqli-1"
    assert stored[0]["provenance"]["finder_model"] == "finder-model"
    # the hunter injected the real class file into the prompt
    assert "attack" in (finder.last_prompt or "").lower()


def test_hunt_drops_malformed_finding(tmp_path, target_repo):
    finder = FakeAdapter('```json\n[{"id": "bad", "title": "x"}]\n```')
    ctx = _ctx(tmp_path, target_repo, finder, FakeAdapter(""))
    result = hunt.run_task(ctx, {"area": "src", "attack_class": "web-protocol-and-auth"})
    assert result["findings"] == 0
    assert result["dropped"] == 1


def test_hunt_retryable_raises(tmp_path, target_repo):
    finder = FakeAdapter("overloaded", outcome=Outcome.RETRYABLE)
    ctx = _ctx(tmp_path, target_repo, finder, FakeAdapter(""))
    with pytest.raises(RuntimeError):
        hunt.run_task(ctx, {"area": "src", "attack_class": "web-protocol-and-auth"})


# ---- validate confirms / rejects on the VERDICT line --------------------

def _complete_finding() -> dict:
    return {
        "id": "sqli-1", "verdict": "needs_validation", "title": "eval on request input",
        "attack_class": "web-protocol-and-auth",
        "threat_model": {"attacker": "remote", "boundary": "input -> code exec"},
        "location": {"file": "src/app.py", "line": 2},
        "poc": {"kind": "input", "content": "x", "observed": "RCE"},
    }


def test_validate_confirms_on_verdict_line(tmp_path, target_repo):
    validator = FakeAdapter("Traced it; reachable.\nVERDICT: confirmed", name="validator-model")
    ctx = _ctx(tmp_path, target_repo, FakeAdapter(""), validator)
    ctx.store.upsert_finding("run-real", target_repo.name, "hunt", _complete_finding())
    result = validate.run_task(ctx, {"finding_id": "sqli-1"})
    assert result["verdict"] == "confirmed"


def test_validate_rejects_on_verdict_line(tmp_path, target_repo):
    validator = FakeAdapter("Defended by a prior check.\nVERDICT: rejected", name="validator-model")
    ctx = _ctx(tmp_path, target_repo, FakeAdapter(""), validator)
    ctx.store.upsert_finding("run-real", target_repo.name, "hunt", _complete_finding())
    result = validate.run_task(ctx, {"finding_id": "sqli-1"})
    assert result["verdict"] == "rejected"


# ---- PoC execution against a pristine copy ------------------------------

from openplow import poc as poc_mod
from openplow.sandbox import Limits


def _sandbox(tmp_path) -> StubSandbox:
    return StubSandbox(tmp_path / "sb", timeout=10, limits=Limits(cpu_seconds=10))


def test_poc_demonstrated(tmp_path, target_repo):
    finding = {
        "poc": {"kind": "script", "content": "print('PWNED')\n", "observed": "PWNED"}
    }
    run = poc_mod.run_poc(_sandbox(tmp_path), target_repo, finding, tmp_path / "w")
    assert run.attempted and run.demonstrated and run.integrity_ok


def test_poc_not_reproduced(tmp_path, target_repo):
    finding = {"poc": {"kind": "script", "content": "import sys; sys.exit(1)\n"}}
    run = poc_mod.run_poc(_sandbox(tmp_path), target_repo, finding, tmp_path / "w")
    assert run.attempted and not run.demonstrated


def test_poc_tampering_detected(tmp_path, target_repo):
    # A PoC that edits a pre-existing source file must be flagged, even on exit 0.
    finding = {"poc": {"kind": "script",
                       "content": "open('src/app.py', 'w').write('tampered')\n"}}
    run = poc_mod.run_poc(_sandbox(tmp_path), target_repo, finding, tmp_path / "w")
    assert run.attempted and not run.integrity_ok and not run.demonstrated


def test_poc_can_spawn_a_shell(tmp_path, target_repo):
    # Regression: a 64-process cap counted every process the user owns on macOS,
    # so no PoC could start a shell and command-injection PoCs never reproduced.
    finding = {"poc": {"kind": "script", "content":
                       "import subprocess; subprocess.run('true', shell=True, check=True); "
                       "print('SPAWNED')\n", "observed": "SPAWNED"}}
    run = poc_mod.run_poc(_sandbox(tmp_path), target_repo, finding, tmp_path / "w")
    assert run.attempted and run.demonstrated


def test_nproc_cap_skipped_only_on_macos():
    from openplow.sandbox import _nproc_capped
    assert not _nproc_capped("darwin")
    assert _nproc_capped("linux")


def test_poc_input_kind_not_executed(tmp_path, target_repo):
    finding = {"poc": {"kind": "input", "content": "x"}}
    run = poc_mod.run_poc(_sandbox(tmp_path), target_repo, finding, tmp_path / "w")
    assert not run.attempted


def test_original_repo_untouched_by_poc(tmp_path, target_repo):
    before = (target_repo / "src" / "app.py").read_text()
    finding = {"poc": {"kind": "script",
                       "content": "open('src/app.py', 'w').write('x')\n"}}
    poc_mod.run_poc(_sandbox(tmp_path), target_repo, finding, tmp_path / "w")
    # PoC ran on a copy; the real target is unchanged.
    assert (target_repo / "src" / "app.py").read_text() == before


def test_validate_confirms_when_poc_reproduces(tmp_path, target_repo):
    validator = FakeAdapter("reachable\nVERDICT: confirmed", name="validator-model")
    ctx = _ctx(tmp_path, target_repo, FakeAdapter(""), validator)
    finding = _complete_finding()
    finding["poc"] = {"kind": "script", "content": "print('ok')\n", "observed": "ok"}
    ctx.store.upsert_finding("run-real", target_repo.name, "hunt", finding)
    result = validate.run_task(ctx, {"finding_id": "sqli-1"})
    assert result["verdict"] == "confirmed"
    assert result["poc_demonstrated"] is True


def test_validate_rejects_when_poc_tampers(tmp_path, target_repo):
    validator = FakeAdapter("VERDICT: confirmed", name="validator-model")
    ctx = _ctx(tmp_path, target_repo, FakeAdapter(""), validator)
    finding = _complete_finding()
    finding["poc"] = {"kind": "script",
                      "content": "open('src/app.py','w').write('x')\n"}
    ctx.store.upsert_finding("run-real", target_repo.name, "hunt", finding)
    result = validate.run_task(ctx, {"finding_id": "sqli-1"})
    assert result["verdict"] == "rejected"


# ---- fail->pass patch gate ----------------------------------------------

def test_apply_snippet_patch(tmp_path):
    repo = tmp_path / "r"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "app.py").write_text("def h(x):\n    return eval(x)\n")
    finding = {"location": {"file": "src/app.py"},
               "patch": "-    return eval(x)\n+    return int(x)"}
    target, _ = poc_mod._prepare_target(repo, tmp_path / "w", {"kind": "script", "content": "x"})
    ok, reason = poc_mod.apply_patch(target, finding)
    assert ok, reason
    assert "return int(x)" in (target / "src" / "app.py").read_text()


def test_patch_gate_passes_on_real_fix(tmp_path):
    repo = tmp_path / "r"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "app.py").write_text("def handler(req):\n    return eval(req)\n")
    finding = {
        "location": {"file": "src/app.py"},
        "poc": {"kind": "script", "observed": "PWNED",
                "content": "import importlib.util\n"
                           "s = importlib.util.spec_from_file_location('app','src/app.py')\n"
                           "m = importlib.util.module_from_spec(s); s.loader.exec_module(m)\n"
                           "print('PWNED', m.handler('6*7'))\n"},
        "patch": "-    return eval(req)\n+    return int(req)",
    }
    gate = poc_mod.run_patch_gate(_sandbox(tmp_path), repo, finding, tmp_path / "g")
    assert gate.attempted and gate.reproduced_before and gate.patch_applied
    assert not gate.reproduced_after and gate.passed


def test_patch_gate_fails_when_patch_does_not_fix(tmp_path):
    repo = tmp_path / "r"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "app.py").write_text("def handler(req):\n    return eval(req)\n")
    finding = {
        "location": {"file": "src/app.py"},
        "poc": {"kind": "script", "observed": "PWNED",
                "content": "import importlib.util\n"
                           "s = importlib.util.spec_from_file_location('app','src/app.py')\n"
                           "m = importlib.util.module_from_spec(s); s.loader.exec_module(m)\n"
                           "print('PWNED', m.handler('6*7'))\n"},
        # a no-op patch (adds a comment) that leaves the vuln intact
        "patch": "-    return eval(req)\n+    return eval(req)  # TODO",
    }
    gate = poc_mod.run_patch_gate(_sandbox(tmp_path), repo, finding, tmp_path / "g")
    assert gate.attempted and gate.reproduced_before and gate.patch_applied
    assert gate.reproduced_after and not gate.passed


def test_patch_gate_not_attempted_without_patch(tmp_path, target_repo):
    finding = {"poc": {"kind": "script", "content": "print('x')\n"}}
    gate = poc_mod.run_patch_gate(_sandbox(tmp_path), target_repo, finding, tmp_path / "g")
    assert not gate.attempted
