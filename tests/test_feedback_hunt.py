"""Hunt-side feedback: reply-level failures become lesson signals, and hunts still
in the queue are built with the lessons recorded before they were claimed."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from openplow import feedback, orchestrator
from openplow.context import RunContext
from openplow.db import Store
from openplow.models import ModelAdapter, ModelResponse, Outcome
from openplow.sandbox import StubSandbox
from openplow.stages import hunt

CLS = "cloud-and-deployment"
OTHER = "client-side"


class _ScriptedModel(ModelAdapter):
    """Finder and validator in one: hunt calls pop scripted replies, a
    ``Finding to disprove`` prompt is answered ``VERDICT: confirmed``. Every call
    is logged so tests can sweep every system prompt the model saw."""

    name = "scripted"
    supports_tools = False

    def __init__(self, replies: list[tuple[str, str]]):
        # Each reply is (text, stop_reason).
        self._replies = list(replies)
        self.calls: list[tuple[str, str]] = []  # (system, prompt), every call
        self.hunts: list[tuple[str, str]] = []  # (system, prompt), hunt calls only
        self.events: list[str] = []

    def complete(self, system, prompt, *, max_tokens=4096):
        self.calls.append((system, prompt))
        if prompt.lstrip().startswith("Finding to disprove"):
            self.events.append("validate")
            return ModelResponse(outcome=Outcome.OK, text="VERDICT: confirmed")
        self.hunts.append((system, prompt))
        self.events.append("hunt")
        text, stop = self._replies.pop(0) if self._replies else ("[]", "end_turn")
        return ModelResponse(outcome=Outcome.OK, text=text, raw={"stop_reason": stop})


class _Outcome(ModelAdapter):
    name = "outcome"

    def __init__(self, outcome: Outcome):
        self._outcome = outcome
        self.calls: list[tuple[str, str]] = []

    def complete(self, system, prompt, *, max_tokens=4096):
        self.calls.append((system, prompt))
        return ModelResponse(outcome=self._outcome, text="", error="boom")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "target"
    for area in ("src", "lib"):
        (root / area).mkdir(parents=True)
        (root / area / "app.py").write_text("import os\n\ndef run(cmd):\n    os.system(cmd)\n")
    return root


def _ctx(tmp_path: Path, repo: Path, model: ModelAdapter, *, feedback_on=True) -> RunContext:
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    store = Store(tmp_path / "db.sqlite")
    store.create_run("run-h", repo.name, model.name)
    return RunContext(run_id="run-h", repo=repo, out_dir=out, store=store, finder=model,
                      validator=model, sandbox=StubSandbox(out / "scratch"),
                      feedback=feedback_on)


def _signals(ctx: RunContext) -> dict[tuple[str, str, str], int]:
    return {(r["attack_class"], r["kind"], r["source"]): r["count"]
            for r in ctx.store.lesson_signals(ctx.run_id)}


def _transcript(ctx: RunContext, area: str, cls: str = CLS) -> dict:
    path = ctx.out_dir / "transcripts" / "hunt" / f"{area}__{cls}__d1.json"
    return json.loads(path.read_text())


def _finding(fid: str, **over) -> dict:
    f = {"id": fid, "title": "shell injection", "attack_class": CLS,
         "threat_model": {"attacker": "remote", "boundary": "input -> shell"},
         "location": {"file": "src/app.py", "line": 4, "symbol": "run"},
         "description": "cmd reaches os.system",
         "poc": {"kind": "script", "content": "print('HIT')", "observed": "HIT"},
         "patch": None}
    f.update(over)
    return f


def _fenced(findings: list[dict]) -> str:
    return "```json\n" + json.dumps(findings) + "\n```"


def _assert_contract(prompt: str, kinds: list[str]) -> None:
    """The prompt holds exactly the templates of ``kinds`` and no other KINDS template."""
    for kind, template in feedback.KINDS.items():
        assert (template in prompt) == (kind in kinds), kind
    assert ("# Lessons" in prompt) == bool(kinds)


def _assert_system_clean(model) -> None:
    """Invariant sweep: lessons never enter any system prompt (the cached prefix)."""
    assert model.calls, "the model was never called"
    for system, _ in model.calls:
        assert "# Lessons" not in system
        assert not any(t in system for t in feedback.KINDS.values())


# ---- no signals: byte-identical prompt ------------------------------------

def test_no_signals_prompt_is_unchanged(tmp_path, repo):
    model = _ScriptedModel([("[]", "end_turn")])
    ctx = _ctx(tmp_path, repo, model)
    expected = hunt._build_prompt(ctx, "src", CLS)  # no lessons argument: the old path
    hunt.run_task(ctx, {"area": "src", "attack_class": CLS})
    assert model.hunts == [expected]
    assert "# Lessons" not in model.hunts[0][1]
    assert _transcript(ctx, "src")["lessons"] == []
    assert _signals(ctx) == {}
    _assert_system_clean(model)


# ---- signals from the existing detection branches -------------------------

def test_unparseable_reply_records_one_signal(tmp_path, repo):
    model = _ScriptedModel([("I could not decide.", "end_turn")])
    ctx = _ctx(tmp_path, repo, model)
    hunt.run_task(ctx, {"area": "src", "attack_class": CLS})
    assert _signals(ctx) == {(CLS, "unparseable", "learned"): 1}
    assert any("unparseable hunter output" in w["item"] for w in ctx.store.wishes("run-h"))
    _assert_system_clean(model)


def test_max_tokens_records_truncated(tmp_path, repo):
    model = _ScriptedModel([("```json\n[]\n```", "max_tokens")])
    ctx = _ctx(tmp_path, repo, model)
    hunt.run_task(ctx, {"area": "src", "attack_class": CLS})
    assert _signals(ctx) == {(CLS, "truncated", "learned"): 1}
    assert any("truncated (max_tokens)" in w["item"] for w in ctx.store.wishes("run-h"))


def test_each_malformed_finding_records_incomplete(tmp_path, repo):
    model = _ScriptedModel([(_fenced([{"id": "a", "title": "t"}, {"id": "b", "title": "t"},
                                      _finding("good")]), "end_turn")])
    ctx = _ctx(tmp_path, repo, model)
    result = hunt.run_task(ctx, {"area": "src", "attack_class": CLS})
    assert result["dropped"] == 2 and result["findings"] == 1
    assert _signals(ctx) == {(CLS, "incomplete_finding", "learned"): 2}
    assert sum("dropped malformed finding" in w["item"] for w in ctx.store.wishes("run-h")) == 2


def test_explicit_empty_answer_records_nothing(tmp_path, repo):
    model = _ScriptedModel([("Nothing found.\n```json\n[]\n```", "end_turn")])
    ctx = _ctx(tmp_path, repo, model)
    hunt.run_task(ctx, {"area": "src", "attack_class": CLS})
    assert _signals(ctx) == {}
    assert ctx.store.wishes("run-h") == []


def test_refusal_records_nothing_but_keeps_wish(tmp_path, repo):
    model = _ScriptedModel([("I can't help with that.", "refusal")])
    ctx = _ctx(tmp_path, repo, model)
    hunt.run_task(ctx, {"area": "src", "attack_class": CLS})
    assert _signals(ctx) == {}
    assert any("hunter refused" in w["item"] for w in ctx.store.wishes("run-h"))


def test_retryable_and_fatal_record_nothing(tmp_path, repo):
    retry = _Outcome(Outcome.RETRYABLE)
    ctx = _ctx(tmp_path, repo, retry)
    with pytest.raises(RuntimeError):
        hunt.run_task(ctx, {"area": "src", "attack_class": CLS})
    fatal = _Outcome(Outcome.FATAL)
    ctx.finder = fatal
    assert hunt.run_task(ctx, {"area": "src", "attack_class": CLS})["fatal"] is True
    assert _signals(ctx) == {}
    _assert_system_clean(retry)
    _assert_system_clean(fatal)


def test_unknown_class_records_nothing_and_does_not_fail(tmp_path, repo):
    model = _ScriptedModel([("garbage", "end_turn")])
    ctx = _ctx(tmp_path, repo, model)
    hunt.run_task(ctx, {"area": "src"})  # attack_class defaults to "unknown"
    assert _signals(ctx) == {}


# ---- the queued-rewrite proof ----------------------------------------------

def _queue_two_hunts(ctx: RunContext, first_cls: str = CLS, second_cls: str = CLS) -> None:
    ctx.store.add_task(f"hunt:src:{first_cls}", ctx.run_id, ctx.repo_name, "hunt",
                       payload={"area": "src", "attack_class": first_cls})
    ctx.store.add_task(f"hunt:lib:{second_cls}", ctx.run_id, ctx.repo_name, "hunt",
                       payload={"area": "lib", "attack_class": second_cls})


def test_queued_hunt_is_rewritten_with_lessons(tmp_path, repo):
    model = _ScriptedModel([("not json at all", "end_turn"), ("[]", "end_turn")])
    ctx = _ctx(tmp_path, repo, model)
    _queue_two_hunts(ctx)
    processed, failed = orchestrator._drain(ctx, sleep=lambda s: None)
    assert (processed, failed) == (2, 0)

    first, second = model.hunts
    _assert_contract(first[1], [])
    assert feedback.KINDS["unparseable"] in second[1]
    assert second[1].endswith(feedback.render(["unparseable"]))
    record = _transcript(ctx, "lib")
    assert record["lessons"] == ["unparseable"]
    assert record["prompt"] == second[1]
    _assert_contract(second[1], record["lessons"])
    _assert_system_clean(model)
    # The system prompt (the cached prefix) is identical for both hunts.
    assert first[0] == second[0]


def test_generic_lesson_crosses_classes(tmp_path, repo):
    model = _ScriptedModel([("not json at all", "end_turn"), ("[]", "end_turn")])
    ctx = _ctx(tmp_path, repo, model)
    _queue_two_hunts(ctx, CLS, OTHER)
    orchestrator._drain(ctx, sleep=lambda s: None)
    record = _transcript(ctx, "lib", OTHER)
    assert record["lessons"] == ["unparseable"]
    _assert_contract(model.hunts[1][1], record["lessons"])


def test_validation_runs_between_hunts(tmp_path, repo):
    """A hunt that files a finding enqueues a validate task; it is claimed before
    the second hunt, and the second prompt holds exactly its transcript's lessons."""
    model = _ScriptedModel([(_fenced([{"id": "bad", "title": "t"}, _finding("good")]),
                             "end_turn"), ("[]", "end_turn")])
    ctx = _ctx(tmp_path, repo, model)
    _queue_two_hunts(ctx)
    orchestrator._drain(ctx, sleep=lambda s: None)

    assert model.events.index("validate") < model.events.index("hunt", 1)
    record = _transcript(ctx, "lib")
    assert "incomplete_finding" in record["lessons"]
    _assert_contract(model.hunts[1][1], record["lessons"])
    _assert_system_clean(model)


def test_feedback_off_drops_learned_keeps_imported(tmp_path, repo):
    model = _ScriptedModel([("not json at all", "end_turn"), ("[]", "end_turn")])
    ctx = _ctx(tmp_path, repo, model, feedback_on=False)
    feedback.import_lessons(ctx.store, ctx.run_id, {"version": 1, "lessons": [
        {"attack_class": CLS, "kind": "poc_timeout", "count": 2}]})
    _queue_two_hunts(ctx)
    orchestrator._drain(ctx, sleep=lambda s: None)

    # Still recorded (the report shows it), just not rendered.
    assert _signals(ctx)[(CLS, "unparseable", "learned")] == 1
    for area, (_, prompt) in zip(("src", "lib"), model.hunts, strict=True):
        record = _transcript(ctx, area)
        assert record["lessons"] == ["poc_timeout"]
        _assert_contract(prompt, record["lessons"])
    _assert_system_clean(model)
