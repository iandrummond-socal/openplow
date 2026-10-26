"""Held-out feedback eval: the verdict's arithmetic and plumbing.

Fixture and fake adapters only, no network. The fakes are installed through the
``openplow.benchmark.build_adapter`` seam; their PoCs are inert one-liners
(``print`` a marker to reproduce, ``sys.exit(1)`` to fail) on toy targets.
"""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from pathlib import Path

import pytest

import openplow.benchmark
from openplow import cli, feedback
from openplow.benchmark import BenchmarkSpec, TargetSpec
from openplow.db import Store
from openplow.feedback_eval import run_feedback_eval
from openplow.models import ModelAdapter, ModelResponse, Outcome

ROOT = Path(__file__).resolve().parent.parent / "benchmarks"
HOLDOUT_DEFAULT = ROOT / "upstream" / "with-decoys.json"
TRAIN_DEFAULT = ROOT / "cve-and-decoys.json"
FEEDBACK_FIXTURE = ROOT / "feedback" / "fixture.json"

CLS = "data-isolation-and-lifecycle"
LESSON = feedback.KINDS["poc_not_reproduced"]
MARKER = "OBSERVED-1"

# What a fake hunter files, given (repo name, area, lesson in prompt, gapfill pass).
Plan = Callable[[str, str, bool, bool], list[dict]]


# ---- fakes and toy targets ------------------------------------------------------

def _finding(fid: str, area: str = "src", *, reproduces: bool) -> dict:
    content = f'print("{MARKER}")' if reproduces else "import sys; sys.exit(1)"
    return {"id": fid, "verdict": "needs_validation", "title": f"placeholder finding {fid}",
            "attack_class": CLS,
            # A distinct placeholder CWE per id, so dedup never folds two fake findings.
            "weakness": f"CWE-{9000 + sum(map(ord, fid))}",
            "threat_model": {"attacker": "placeholder", "boundary": "placeholder"},
            "location": {"file": f"{area}/app.py", "line": 1, "symbol": "add"},
            "description": "placeholder description",
            "poc": {"kind": "script", "content": content, "observed": MARKER},
            "patch": None}


def _grep(prompt: str, label: str) -> str:
    for line in prompt.splitlines():
        if line.startswith(label):
            return line[len(label):].strip()
    return ""


class _Fake(ModelAdapter):
    """Finder and validator in one. A ``Finding to disprove`` prompt is answered
    ``VERDICT: confirmed``; a hunt of ``CLS`` files whatever ``plan`` says, every
    other class files nothing."""

    name = "fake"
    supports_tools = False

    def __init__(self, plan: Plan, *, usage: dict | None = None):
        self._plan = plan
        self._usage = usage
        self.hunts: list[str] = []

    def complete(self, system, prompt, *, max_tokens=4096):
        raw = {"usage": dict(self._usage), "model": "claude-opus-5-5"} if self._usage else {}
        if prompt.lstrip().startswith("Finding to disprove"):
            return ModelResponse(outcome=Outcome.OK, text="VERDICT: confirmed", raw=raw)
        self.hunts.append(prompt)
        findings: list[dict] = []
        if _grep(prompt, "Attack class:") == CLS:
            findings = self._plan(_grep(prompt, "Repo:"), _grep(prompt, "Area:"),
                                  LESSON in prompt, "gapfill pass" in prompt)
        return ModelResponse(outcome=Outcome.OK,
                             text="```json\n" + json.dumps(findings) + "\n```", raw=raw)


def _install(monkeypatch, fake: ModelAdapter) -> list[str]:
    """Route every adapter the benchmark builds to ``fake``; returns the specs asked for."""
    asked: list[str] = []

    def factory(spec, *, effort=None, budget=None):
        asked.append(spec)
        return fake

    monkeypatch.setattr(openplow.benchmark, "build_adapter", factory)
    return asked


def _target(root: Path, name: str, areas: tuple[str, ...] = ("src",), tag: str = "") -> Path:
    path = root / name
    for area in areas:
        (path / area).mkdir(parents=True, exist_ok=True)
        (path / area / "app.py").write_text(f"def add(a, b):\n    return a + b\n# {tag or name}\n")
    return path


def _spec(root: Path, name: str, targets: list[tuple[str, bool]],
          areas: tuple[str, ...] = ("src",)) -> BenchmarkSpec:
    for tname, _ in targets:
        _target(root, tname, areas)
    return BenchmarkSpec(name=name, base_dir=root,
                         targets=[TargetSpec(name=t, path=t, decoy=d) for t, d in targets])


def _write_spec(path: Path, targets: list[tuple[str, bool]]) -> Path:
    for tname, _ in targets:
        _target(path.parent, tname)
    path.write_text(json.dumps({"name": path.stem, "targets": [
        {"name": t, "path": t, **({"decoy": True} if d else {})} for t, d in targets]}))
    return path


def _train_plan(repo: str, area: str, lesson: bool, gapfill: bool) -> list[dict]:
    """On the training target, file one finding whose PoC exits 1."""
    return [_finding("t-bad", area, reproduces=False)] if repo == "train-a" else []


def _eval(tmp_path: Path, holdout: BenchmarkSpec, **kw):
    kw.setdefault("train_spec", _spec(tmp_path / "train", "train", [("train-a", False)]))
    return run_feedback_eval(holdout, finder_spec="fake", validator_spec=None,
                             sandbox_kind="stub", out_dir=tmp_path / "out", **kw)


# ---- free end-to-end on the default split ---------------------------------------

def test_fixture_end_to_end_on_the_default_split(tmp_path):
    fixture = f"fixture:{FEEDBACK_FIXTURE}"
    out = tmp_path / "out"
    report = run_feedback_eval(openplow.benchmark.load_spec(HOLDOUT_DEFAULT),
                               train_spec=openplow.benchmark.load_spec(TRAIN_DEFAULT),
                               finder_spec=fixture, validator_spec=fixture,
                               sandbox_kind="stub", out_dir=out)
    for name in ("lessons.json", "feedback-eval.json", "feedback-eval.md"):
        assert (out / name).is_file(), name
    lessons = json.loads((out / "lessons.json").read_text())
    feedback.check_lessons(lessons)
    kinds = {row["kind"] for row in lessons["lessons"]}
    assert {"poc_not_reproduced", "incomplete_finding"} <= kinds
    for totals in (report.baseline_totals, report.lessons_totals):
        assert {"confirmed_recall", "false_positives", "rejection_rate",
                "candidates_total", "cells_covered"} <= set(totals)
    assert report.train_totals is not None
    assert report.verdict == "no change"
    data = json.loads((out / "feedback-eval.json").read_text())
    assert data["verdict"] == "no change"


# ---- verdicts from a fake that listens to the lessons ---------------------------

def _improving_plan(repo: str, area: str, lesson: bool, gapfill: bool) -> list[dict]:
    if repo == "train-a":
        return _train_plan(repo, area, lesson, gapfill)
    if lesson:
        return [_finding("h-good", area, reproduces=True),
                _finding("h-fixed", area, reproduces=True)]
    return [_finding("h-good", area, reproduces=True),
            _finding("h-bad", area, reproduces=False)]


def test_lessons_that_help_on_held_out_code_are_improved(tmp_path, monkeypatch):
    fake = _Fake(_improving_plan)
    _install(monkeypatch, fake)
    report = _eval(tmp_path, _spec(tmp_path / "hold", "hold", [("hold-b", False)]))
    assert report.lessons == {"version": 1, "lessons": [
        {"attack_class": CLS, "kind": "poc_not_reproduced", "count": 1}]}
    a, b = report.baseline_totals, report.lessons_totals
    assert a["candidates_total"] == b["candidates_total"] == 2
    assert a["rejection_rate"] == 0.5 and b["rejection_rate"] == 0.0
    assert report.verdict == "improved", report.verdict_reason
    assert "rejection rate fell" in report.verdict_reason
    # The held-out prompts really differed by the lesson, and only in arm B.
    assert any(LESSON in p and "Repo: hold-b" in p for p in fake.hunts)
    assert any(LESSON not in p and "Repo: hold-b" in p for p in fake.hunts)


def test_filing_nothing_is_never_a_win(tmp_path, monkeypatch):
    def plan(repo, area, lesson, gapfill):
        if repo == "train-a":
            return _train_plan(repo, area, lesson, gapfill)
        if lesson:
            return []
        return [_finding("h-good", area, reproduces=True),
                _finding("h-bad", area, reproduces=False)]

    _install(monkeypatch, _Fake(plan))
    report = _eval(tmp_path, _spec(tmp_path / "hold", "hold", [("hold-b", False)]))
    assert report.lessons_totals["rejection_rate"] == 0.0
    assert report.lessons_totals["candidates_total"] < report.baseline_totals["candidates_total"]
    assert report.verdict == "no change"
    assert "fewer candidates" in report.verdict_reason


def _decoy_plan(repo: str, area: str, lesson: bool, gapfill: bool) -> list[dict]:
    if repo == "train-a":
        return _train_plan(repo, area, lesson, gapfill)
    return [_finding("d-good", area, reproduces=True)] if lesson else []


def test_a_confirmed_finding_on_a_decoy_is_regressed(tmp_path, monkeypatch):
    _install(monkeypatch, _Fake(_decoy_plan))
    report = _eval(tmp_path, _spec(tmp_path / "hold", "hold", [("hold-decoy", True)]))
    assert report.baseline_totals["false_positives"] == 0
    assert report.lessons_totals["false_positives"] == 1
    assert report.verdict == "regressed"
    assert "false positives" in report.verdict_reason


def test_cli_exits_1_on_regressed(tmp_path, monkeypatch, capsys):
    _install(monkeypatch, _Fake(_decoy_plan))
    (tmp_path / "train").mkdir()
    (tmp_path / "hold").mkdir()
    train = _write_spec(tmp_path / "train" / "train.json", [("train-a", False)])
    hold = _write_spec(tmp_path / "hold" / "hold.json", [("hold-decoy", True)])
    out = tmp_path / "out"
    code = cli.main(["feedback-eval", str(hold), "--train", str(train), "--adapter", "fake",
                     "--out", str(out)])
    assert code == 1
    assert "verdict: regressed" in capsys.readouterr().out
    assert (out / "feedback-eval.md").is_file()


# ---- compare modes -----------------------------------------------------------------

def test_in_run_mode_compares_feedback_off_and_on(tmp_path, monkeypatch):
    def plan(repo, area, lesson, gapfill):
        # Each area's hunt fails until the lesson reaches its prompt.
        if lesson:
            return [_finding(f"{area}-good", area, reproduces=True)]
        return [_finding(f"{area}-bad", area, reproduces=False)]

    asked = _install(monkeypatch, _Fake(plan))
    holdout = _spec(tmp_path / "hold", "hold", [("hold-b", False)], areas=("lib", "src"))
    report = run_feedback_eval(holdout, compare="in-run", finder_spec="fake",
                               validator_spec=None, sandbox_kind="stub",
                               out_dir=tmp_path / "out")
    assert report.compare == "in-run" and report.lessons is None
    assert report.train_totals is None and not (tmp_path / "out" / "train").exists()
    assert report.baseline_totals != report.lessons_totals
    assert report.baseline_totals["rejection_rate"] == 1.0
    assert report.lessons_totals["rejection_rate"] < 1.0
    assert report.verdict == "improved", report.verdict_reason
    assert asked


def test_in_run_with_train_spec_is_refused(tmp_path, monkeypatch):
    _install(monkeypatch, _Fake(_train_plan))
    holdout = _spec(tmp_path / "hold", "hold", [("hold-b", False)])
    with pytest.raises(ValueError, match="does not train"):
        _eval(tmp_path, holdout, compare="in-run")
    assert not (tmp_path / "out").exists()


def test_imported_without_train_spec_is_refused(tmp_path, monkeypatch):
    _install(monkeypatch, _Fake(_train_plan))
    holdout = _spec(tmp_path / "hold", "hold", [("hold-b", False)])
    with pytest.raises(ValueError, match="needs a training benchmark"):
        run_feedback_eval(holdout, finder_spec="fake", validator_spec=None,
                          sandbox_kind="stub", out_dir=tmp_path / "out")
    assert not (tmp_path / "out").exists()


# ---- refusals -------------------------------------------------------------------------

def test_cli_refuses_a_paid_adapter_without_max_cost(tmp_path, monkeypatch, capsys):
    def factory(spec, *, effort=None, budget=None):
        raise AssertionError("build_adapter must not be called")

    monkeypatch.setattr(openplow.benchmark, "build_adapter", factory)
    (tmp_path / "train").mkdir()
    (tmp_path / "hold").mkdir()
    train = _write_spec(tmp_path / "train" / "train.json", [("train-a", False)])
    hold = _write_spec(tmp_path / "hold" / "hold.json", [("hold-b", False)])
    out = tmp_path / "out"
    code = cli.main(["feedback-eval", str(hold), "--train", str(train),
                     "--adapter", "anthropic:x", "--out", str(out)])
    assert code == 2
    assert "set --max-cost" in capsys.readouterr().err
    assert not out.exists()


def test_same_spec_as_train_and_holdout_is_refused(tmp_path, monkeypatch):
    _install(monkeypatch, _Fake(_train_plan))
    spec = _spec(tmp_path / "train", "train", [("train-a", False)])
    out = tmp_path / "out"
    with pytest.raises(ValueError, match="same name"):
        run_feedback_eval(spec, train_spec=spec, finder_spec="fake", validator_spec=None,
                          sandbox_kind="stub", out_dir=out)
    assert not (out / "train").exists()


def test_a_renamed_copy_of_a_train_target_is_refused(tmp_path, monkeypatch):
    _install(monkeypatch, _Fake(_train_plan))
    train = _spec(tmp_path / "train", "train", [("train-a", False)])
    (tmp_path / "hold").mkdir()
    shutil.copytree(tmp_path / "train" / "train-a", tmp_path / "hold" / "renamed")
    holdout = BenchmarkSpec(name="hold", base_dir=tmp_path / "hold",
                            targets=[TargetSpec(name="renamed", path="renamed")])
    out = tmp_path / "out"
    with pytest.raises(ValueError, match="same source"):
        run_feedback_eval(holdout, train_spec=train, finder_spec="fake", validator_spec=None,
                          sandbox_kind="stub", out_dir=out)
    assert not (out / "train").exists()


# ---- cap, repeats, leakage, cold start ------------------------------------------------

def test_an_exhausted_cap_is_incomplete_never_improved(tmp_path, monkeypatch):
    fake = _Fake(_improving_plan, usage={"input_tokens": 100_000, "output_tokens": 10_000})
    _install(monkeypatch, fake)
    report = _eval(tmp_path, _spec(tmp_path / "hold", "hold", [("hold-b", False)]),
                   max_cost=0.0)
    assert report.verdict == "incomplete"
    assert "spending cap reached" in report.verdict_reason
    assert any(r.startswith("train:") for r in report.incomplete_reasons)
    assert fake.hunts == []  # nothing ran under a cap that was already reached


def test_repeats_alternate_the_arm_order(tmp_path, monkeypatch):
    _install(monkeypatch, _Fake(_improving_plan))
    report = _eval(tmp_path, _spec(tmp_path / "hold", "hold", [("hold-b", False)]), repeats=2)
    assert report.arm_order == ["baseline-1", "lessons-1", "lessons-2", "baseline-2"]
    dirs = sorted(p.name for p in (tmp_path / "out").glob("holdout-*") if p.is_dir())
    assert dirs == ["holdout-baseline-1", "holdout-baseline-2",
                    "holdout-lessons-1", "holdout-lessons-2"]
    assert report.repeats == 2 and report.verdict == "improved"


def test_held_out_runs_never_reach_the_lessons_file(tmp_path, monkeypatch):
    _install(monkeypatch, _Fake(_improving_plan))
    real = openplow.benchmark.run_benchmark
    before: list[bytes] = []

    def spy(spec, *, out_dir, **kw):
        if out_dir.name.startswith("holdout-") and not before:
            before.append((out_dir.parent / "lessons.json").read_bytes())
        return real(spec, out_dir=out_dir, **kw)

    monkeypatch.setattr(openplow.benchmark, "run_benchmark", spy)
    _eval(tmp_path, _spec(tmp_path / "hold", "hold", [("hold-b", False)]))
    out = tmp_path / "out"
    assert before and (out / "lessons.json").read_bytes() == before[0]
    # The held-out baseline did learn a signal of its own; it stayed in its own store.
    store = Store(out / "holdout-baseline-1" / "benchmark.sqlite")
    try:
        rows = store._conn.execute(
            "SELECT kind, source FROM lessons WHERE kind = 'poc_not_reproduced'").fetchall()
    finally:
        store.close()
    assert ("poc_not_reproduced", "learned") in [tuple(r) for r in rows]


def test_cold_start_creates_the_out_dir(tmp_path, monkeypatch):
    _install(monkeypatch, _Fake(_train_plan))
    out = tmp_path / "not" / "there" / "yet"
    assert not out.exists()
    report = run_feedback_eval(_spec(tmp_path / "hold", "hold", [("hold-b", False)]),
                               train_spec=_spec(tmp_path / "train", "train",
                                                [("train-a", False)]),
                               finder_spec="fake", validator_spec=None, sandbox_kind="stub",
                               out_dir=out)
    assert (out / "feedback-eval.json").is_file() and (out / "lessons.json").is_file()
    assert report.verdict == "no change"


# ---- review fixes ------------------------------------------------------------------

def test_cli_exits_2_not_1_on_a_malformed_spec(tmp_path, monkeypatch, capsys):
    """1 means regressed; a spec that cannot be read must never look like one."""
    _install(monkeypatch, _Fake(_train_plan))
    (tmp_path / "train").mkdir()
    train = _write_spec(tmp_path / "train" / "train.json", [("train-a", False)])
    hold = tmp_path / "hold.json"
    hold.write_text(json.dumps({"name": "hold", "targets": [{"path": "hold-b"}]}))
    out = tmp_path / "out"
    code = cli.main(["feedback-eval", str(hold), "--train", str(train), "--adapter", "fake",
                     "--out", str(out)])
    assert code == 2
    assert "needs a non-empty string 'name'" in capsys.readouterr().err
    assert not out.exists()


@pytest.mark.parametrize("which", ["train", "holdout"])
@pytest.mark.parametrize("state", ["missing", "empty"])
def test_a_missing_or_empty_target_dir_is_refused_by_its_own_name(tmp_path, monkeypatch,
                                                                  which, state):
    _install(monkeypatch, _Fake(_train_plan))
    train = _spec(tmp_path / "train", "train", [("train-a", False)])
    holdout = _spec(tmp_path / "hold", "hold", [("hold-b", False)])
    spec, name = (train, "train-a") if which == "train" else (holdout, "hold-b")
    shutil.rmtree(spec.base_dir / name)
    if state == "empty":
        (spec.base_dir / name).mkdir()
    out = tmp_path / "out"
    with pytest.raises(ValueError, match=f"target '{name}': directory .* is missing or empty"):
        run_feedback_eval(holdout, train_spec=train, finder_spec="fake", validator_spec=None,
                          sandbox_kind="stub", out_dir=out)
    assert not out.exists()


@pytest.mark.parametrize("held_inside", [True, False])
def test_a_target_nested_in_the_other_set_is_refused(tmp_path, monkeypatch, held_inside):
    """A directory inside another holds part of its code under a new digest, so
    neither the name nor the content check would catch it."""
    _install(monkeypatch, _Fake(_train_plan))
    _target(tmp_path, "outer", areas=("src", "lib"))
    outer = TargetSpec(name="outer", path="outer")
    inner = TargetSpec(name="inner", path="outer/lib")
    train = BenchmarkSpec(name="train", base_dir=tmp_path,
                          targets=[outer if held_inside else inner])
    holdout = BenchmarkSpec(name="hold", base_dir=tmp_path,
                            targets=[inner if held_inside else outer])
    out = tmp_path / "out"
    with pytest.raises(ValueError, match="'inner'.*'outer'|'outer'.*'inner'") as exc:
        run_feedback_eval(holdout, train_spec=train, finder_spec="fake", validator_spec=None,
                          sandbox_kind="stub", out_dir=out)
    assert "overlap" in str(exc.value)
    assert not out.exists()


def test_one_budget_reaches_every_phase(tmp_path, monkeypatch):
    _install(monkeypatch, _Fake(_improving_plan))
    real = openplow.benchmark.run_benchmark
    seen: list[tuple[str, object]] = []

    def spy(spec, *, out_dir, **kw):
        seen.append((out_dir.name, kw.get("budget")))
        assert kw.get("max_cost") is None, "a phase must not build a cap of its own"
        return real(spec, out_dir=out_dir, **kw)

    monkeypatch.setattr(openplow.benchmark, "run_benchmark", spy)
    _eval(tmp_path, _spec(tmp_path / "hold", "hold", [("hold-b", False)]),
          max_cost=100.0, repeats=2)
    assert [name for name, _ in seen] == ["train", "holdout-baseline-1", "holdout-lessons-1",
                                          "holdout-lessons-2", "holdout-baseline-2"]
    budgets = [b for _, b in seen]
    assert budgets[0] is not None and budgets[0].limit == 100.0
    assert len(set(map(id, budgets))) == 1


@pytest.mark.parametrize("decoy", [False, True])
def test_zero_lessons_is_no_change_whatever_the_noise(tmp_path, monkeypatch, decoy):
    """Training learns nothing, so both arms run identical prompts; the fake still
    files a confirmed finding in arm B only (noise). On a real target that would
    read as a coverage win, on a decoy as a false-positive regression."""
    arm: dict[str, str] = {}

    def plan(repo, area, lesson, gapfill):
        assert not lesson
        if repo == "hold-b" and arm.get("now") == "lessons":
            return [_finding("noise", area, reproduces=True)]
        return []

    _install(monkeypatch, _Fake(plan))
    real = openplow.benchmark.run_benchmark

    def spy(spec, *, out_dir, **kw):
        arm["now"] = out_dir.name.split("-")[1] if out_dir.name.startswith("holdout-") else ""
        return real(spec, out_dir=out_dir, **kw)

    monkeypatch.setattr(openplow.benchmark, "run_benchmark", spy)
    report = _eval(tmp_path, _spec(tmp_path / "hold", "hold", [("hold-b", decoy)]))
    assert report.lessons == {"version": 1, "lessons": []}
    a, b = report.baseline_totals, report.lessons_totals
    if decoy:
        assert b["false_positives"] > a["false_positives"]
    else:
        assert b["cells_covered"] > a["cells_covered"]
    assert report.verdict == "no change", report.verdict_reason
    assert "any difference is noise" in report.verdict_reason
