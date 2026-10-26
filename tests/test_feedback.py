"""Tests for the feedback-loop foundation: kinds, store, render, export/import,
claim order and the report section."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from openplow import feedback
from openplow.context import RunContext
from openplow.db import Store
from openplow.models import StubAdapter
from openplow.sandbox import StubSandbox
from openplow.stages import report
from openplow.stages.recon import ATTACK_CLASSES

WEB = "web-protocol-and-auth"
DATA = "data-isolation-and-lifecycle"


def _make_ctx(tmp_path: Path, run_id: str = "run-x", *, feedback_on: bool = True,
              db: str = "db.sqlite") -> RunContext:
    repo = tmp_path / "target"
    repo.mkdir(exist_ok=True)
    out = tmp_path / f"out-{run_id}"
    out.mkdir(exist_ok=True)
    store = Store(tmp_path / db)
    store.create_run(run_id, "target", "stub")
    return RunContext(run_id=run_id, repo=repo, out_dir=out, store=store,
                      finder=StubAdapter(), validator=StubAdapter(),
                      sandbox=StubSandbox(out / "scratch"), feedback=feedback_on)


@pytest.fixture
def ctx(tmp_path: Path) -> RunContext:
    return _make_ctx(tmp_path)


def _rows(ctx: RunContext) -> list[tuple[str, str, str, int]]:
    return [(r["attack_class"], r["kind"], r["source"], r["count"])
            for r in ctx.store.lesson_signals(ctx.run_id)]


# ---- vocabulary ---------------------------------------------------------

def test_vocabulary_shape():
    assert len(feedback.KINDS) == 11
    assert feedback.GENERIC_KINDS == {"unparseable", "truncated", "incomplete_finding"}
    assert feedback.TRAINING_KINDS == {"missed_known", "false_positive"}
    assert feedback.GENERIC_KINDS <= set(feedback.KINDS)
    assert feedback.TRAINING_KINDS <= set(feedback.KINDS)
    assert feedback.MAX_LESSONS == 6
    assert feedback.LESSONS_VERSION == 1


def test_context_feedback_defaults_on(tmp_path: Path):
    store = Store(tmp_path / "db.sqlite")
    c = RunContext(run_id="r", repo=tmp_path, out_dir=tmp_path, store=store,
                   finder=StubAdapter(), validator=StubAdapter(),
                   sandbox=StubSandbox(tmp_path / "s"))
    assert c.feedback is True


# ---- record -------------------------------------------------------------

def test_record_rejects_unknown_kind(ctx: RunContext):
    with pytest.raises(ValueError, match="unknown lesson kind"):
        feedback.record(ctx, WEB, "made_up")
    assert _rows(ctx) == []


def test_record_accepts_all_eleven(ctx: RunContext):
    for kind in feedback.KINDS:
        feedback.record(ctx, WEB, kind)
    assert {r[1] for r in _rows(ctx)} == set(feedback.KINDS)
    assert all(r[2] == "learned" and r[3] == 1 for r in _rows(ctx))


def test_record_skips_unknown_class(ctx: RunContext):
    feedback.record(ctx, "unknown", "unparseable")
    assert _rows(ctx) == []


# ---- store grid ---------------------------------------------------------

def test_first_signal_inserts_then_increments(tmp_path: Path):
    c = _make_ctx(tmp_path, "fresh-run", db="fresh.sqlite")
    assert feedback.lessons_for(c, WEB) == []
    feedback.record(c, WEB, "disproved")
    assert _rows(c) == [(WEB, "disproved", "learned", 1)]
    assert feedback.lessons_for(c, WEB) == ["disproved"]
    feedback.record(c, WEB, "disproved", n=2)
    assert _rows(c) == [(WEB, "disproved", "learned", 3)]


def test_imported_and_learned_are_separate_rows_and_sum(ctx: RunContext):
    feedback.record(ctx, WEB, "disproved")
    ctx.store.set_lesson_signal(ctx.run_id, WEB, "disproved", count=4)
    assert _rows(ctx) == [(WEB, "disproved", "imported", 4), (WEB, "disproved", "learned", 1)]
    # Summed: 5 beats a learned 3 on another kind.
    feedback.record(ctx, WEB, "poc_timeout", n=3)
    assert feedback.lessons_for(ctx, WEB) == ["disproved", "poc_timeout"]


def test_feedback_off_still_records_but_uses_only_imported(tmp_path: Path):
    c = _make_ctx(tmp_path, feedback_on=False)
    feedback.record(c, WEB, "poc_timeout", n=5)
    c.store.set_lesson_signal(c.run_id, WEB, "disproved", count=1)
    assert (WEB, "poc_timeout", "learned", 5) in _rows(c)
    assert feedback.lessons_for(c, WEB) == ["disproved"]
    assert feedback.export_lessons(c.store, [c.run_id])["lessons"] == [
        {"attack_class": WEB, "kind": "disproved", "count": 1},
        {"attack_class": WEB, "kind": "poc_timeout", "count": 5},
    ]


def test_signals_survive_reopen(tmp_path: Path):
    c = _make_ctx(tmp_path)
    feedback.record(c, WEB, "truncated", n=2)
    feedback.record(c, WEB, "disproved")
    before = feedback.lessons_for(c, WEB)
    c.store.close()
    c.store = Store(tmp_path / "db.sqlite")
    assert feedback.lessons_for(c, WEB) == before == ["truncated", "disproved"]


# ---- lessons_for --------------------------------------------------------

def test_class_kinds_stay_in_class_generic_kinds_cross(ctx: RunContext):
    feedback.record(ctx, DATA, "poc_not_reproduced")
    feedback.record(ctx, DATA, "unparseable")
    assert feedback.lessons_for(ctx, WEB) == ["unparseable"]
    assert sorted(feedback.lessons_for(ctx, DATA)) == ["poc_not_reproduced", "unparseable"]


def test_generic_kind_sums_across_classes(ctx: RunContext):
    feedback.record(ctx, DATA, "truncated", n=2)
    feedback.record(ctx, WEB, "truncated", n=2)
    feedback.record(ctx, WEB, "disproved", n=3)
    assert feedback.lessons_for(ctx, WEB) == ["truncated", "disproved"]


def test_lessons_for_caps_and_orders(ctx: RunContext):
    counts = {"poc_not_reproduced": 2, "poc_tampered": 2, "poc_timeout": 9,
              "poc_not_executable": 1, "disproved": 5, "patch_failed": 2,
              "missed_known": 1, "unparseable": 2}
    for kind, n in counts.items():
        feedback.record(ctx, WEB, kind, n=n)
    got = feedback.lessons_for(ctx, WEB)
    assert len(got) == feedback.MAX_LESSONS
    # count desc, then kind name.
    assert got == ["poc_timeout", "disproved", "patch_failed", "poc_not_reproduced",
                   "poc_tampered", "unparseable"]


# ---- render -------------------------------------------------------------

def test_render_empty_is_empty_string():
    assert feedback.render([]) == ""


def test_render_contains_each_template_verbatim():
    kinds = list(feedback.KINDS)
    text = feedback.render(kinds)
    assert text.startswith("# Lessons from earlier tasks\n")
    for kind in kinds:
        assert f"- {feedback.KINDS[kind]}" in text
    one = feedback.render(["unparseable"])
    assert one == ("# Lessons from earlier tasks\n"
                   "These come from failures earlier in this audit (or from earlier audits). "
                   "Apply them.\n"
                   f"- {feedback.KINDS['unparseable']}")


# ---- export / import ----------------------------------------------------

def test_export_sums_runs_filters_and_sorts(tmp_path: Path):
    a = _make_ctx(tmp_path, "run-a")
    b = _make_ctx(tmp_path, "run-b")
    feedback.record(a, WEB, "disproved", n=2)
    feedback.record(b, WEB, "disproved", n=1)
    a.store.set_lesson_signal("run-b", WEB, "disproved", count=1)
    feedback.record(b, DATA, "poc_timeout")
    feedback.record(a, DATA, "unparseable", n=3)
    out = feedback.export_lessons(a.store, ["run-a", "run-b"])
    assert out == {"version": 1, "lessons": [
        {"attack_class": DATA, "kind": "poc_timeout", "count": 1},
        {"attack_class": DATA, "kind": "unparseable", "count": 3},
        {"attack_class": WEB, "kind": "disproved", "count": 4},
    ]}
    high = feedback.export_lessons(a.store, ["run-a", "run-b"], min_count=3)
    assert [(r["attack_class"], r["kind"]) for r in high["lessons"]] == [
        (DATA, "unparseable"), (WEB, "disproved")]
    # Deterministic: the same input exports the same bytes.
    assert json.dumps(out) == json.dumps(feedback.export_lessons(a.store, ["run-a", "run-b"]))


def test_export_drops_unknown_class_written_through_store(ctx: RunContext):
    ctx.store.add_lesson_signal(ctx.run_id, "unknown", "missed_known")
    ctx.store.add_lesson_signal(ctx.run_id, WEB, "not_a_kind")
    ctx.store.add_lesson_signal(ctx.run_id, WEB, "missed_known")
    out = feedback.export_lessons(ctx.store, [ctx.run_id])
    assert out["lessons"] == [{"attack_class": WEB, "kind": "missed_known", "count": 1}]
    assert feedback.check_lessons(out) == out


def test_import_twice_leaves_counts_unchanged(ctx: RunContext):
    data = {"version": 1, "lessons": [{"attack_class": WEB, "kind": "disproved", "count": 3}]}
    assert feedback.import_lessons(ctx.store, ctx.run_id, data) == 1
    assert feedback.import_lessons(ctx.store, ctx.run_id, data) == 1
    assert _rows(ctx) == [(WEB, "disproved", "imported", 3)]


def test_round_trip_export_check_import(tmp_path: Path):
    train = _make_ctx(tmp_path, "train")
    feedback.record(train, WEB, "disproved", n=2)
    feedback.record(train, WEB, "poc_tampered")
    feedback.record(train, DATA, "truncated", n=4)
    exported = feedback.export_lessons(train.store, ["train"])
    path = tmp_path / "lessons.json"
    path.write_text(json.dumps(exported))
    loaded = feedback.load_lessons(path)
    assert loaded == feedback.check_lessons(exported) == exported

    held = _make_ctx(tmp_path, "held", feedback_on=False)
    assert feedback.import_lessons(held.store, "held", loaded) == 3
    for cls in (WEB, DATA):
        assert feedback.lessons_for(held, cls) == feedback.lessons_for(train, cls)


def _good() -> dict:
    return {"version": 1, "lessons": [{"attack_class": WEB, "kind": "disproved", "count": 1}]}


@pytest.mark.parametrize(("mutate", "message"), [
    (lambda d: d["lessons"][0].update(kind="made_up"), "unknown kind"),
    (lambda d: d["lessons"][0].update(attack_class="unknown"), "unknown attack class"),
    (lambda d: d["lessons"][0].update(count=0), "positive integer"),
    (lambda d: d["lessons"][0].update(count=-2), "positive integer"),
    (lambda d: d["lessons"][0].update(count=1.5), "positive integer"),
    (lambda d: d["lessons"][0].update(count="3"), "positive integer"),
    (lambda d: d["lessons"][0].update(count=True), "positive integer"),
    (lambda d: d["lessons"][0].update(text="src/app.py handler"), "unknown field"),
    (lambda d: d["lessons"][0].pop("count"), "missing field"),
    (lambda d: d.update(notes="hi"), "unknown top-level key"),
    (lambda d: d.update(version=2), "version"),
    (lambda d: d.pop("version"), "version"),
    (lambda d: d.update(lessons={}), "must be a list"),
    (lambda d: d["lessons"].append(dict(d["lessons"][0])), "repeats"),
])
def test_check_lessons_refuses(mutate, message):
    data = _good()
    mutate(data)
    with pytest.raises(ValueError, match=message):
        feedback.check_lessons(data)


def test_check_lessons_refuses_non_object():
    with pytest.raises(ValueError, match="JSON object"):
        feedback.check_lessons([])


def test_load_lessons_refuses_bad_json(tmp_path: Path):
    p = tmp_path / "bad.json"
    p.write_text("{not json")
    with pytest.raises(ValueError, match="not valid JSON"):
        feedback.load_lessons(p)


def test_import_refuses_bad_file_and_writes_nothing(ctx: RunContext):
    bad = _good()
    bad["lessons"].append({"attack_class": WEB, "kind": "disproved2", "count": 1})
    with pytest.raises(ValueError):
        feedback.import_lessons(ctx.store, ctx.run_id, bad)
    assert _rows(ctx) == []


def test_every_attack_class_is_legal_in_a_file():
    data = {"version": 1, "lessons": [
        {"attack_class": c, "kind": "disproved", "count": 1} for c in ATTACK_CLASSES]}
    assert feedback.check_lessons(data) == data


# ---- old database -------------------------------------------------------

def test_old_database_gains_lessons_table(tmp_path: Path):
    path = tmp_path / "old.sqlite"
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE runs (run_id TEXT PRIMARY KEY, repo TEXT NOT NULL,
            adapter TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'running',
            created_at REAL NOT NULL, updated_at REAL NOT NULL);
        INSERT INTO runs VALUES ('old-run', 'target', 'stub', 'done', 1.0, 1.0);
    """)
    conn.commit()
    conn.close()
    assert "lessons" not in {r[0] for r in sqlite3.connect(path).execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}

    store = Store(path)
    store.add_lesson_signal("old-run", WEB, "disproved")
    assert store.lesson_signals("old-run") == [
        {"attack_class": WEB, "kind": "disproved", "source": "learned", "count": 1}]
    assert store.get_run("old-run")["status"] == "done"


# ---- claim order --------------------------------------------------------

def test_validations_are_claimed_before_hunts(ctx: RunContext):
    s = ctx.store
    s.add_task("hunt:a", ctx.run_id, "target", "hunt", {"n": "A"})
    s.add_task("hunt:b", ctx.run_id, "target", "hunt", {"n": "B"})
    s.add_task("validate:v", ctx.run_id, "target", "validate", {"n": "V"})
    order = []
    while (t := s.next_pending(ctx.run_id)) is not None:
        order.append(t.task_id)
    assert order == ["validate:v", "hunt:a", "hunt:b"]


def test_stage_filtered_claim_keeps_enqueue_order(ctx: RunContext):
    s = ctx.store
    s.add_task("hunt:a", ctx.run_id, "target", "hunt", {"n": "A"})
    s.add_task("hunt:b", ctx.run_id, "target", "hunt", {"n": "B"})
    s.add_task("validate:v", ctx.run_id, "target", "validate", {"n": "V"})
    assert s.next_pending(ctx.run_id, stage="hunt").task_id == "hunt:a"


def test_rowid_breaks_created_at_ties(ctx: RunContext, monkeypatch: pytest.MonkeyPatch):
    from openplow import db

    monkeypatch.setattr(db, "_now", lambda: 1000.0)
    s = ctx.store
    for name in ("c", "a", "b"):
        s.add_task(f"hunt:{name}", ctx.run_id, "target", "hunt", {"n": name})
    got = [s.next_pending(ctx.run_id).task_id for _ in range(3)]
    assert got == ["hunt:c", "hunt:a", "hunt:b"]


# ---- report -------------------------------------------------------------

def test_report_writes_feedback_table_when_signals(ctx: RunContext):
    feedback.record(ctx, WEB, "poc_not_reproduced", n=2)
    ctx.store.set_lesson_signal(ctx.run_id, WEB, "disproved", count=1)
    report.run_task(ctx, {})
    text = (ctx.out_dir / "REPORT.md").read_text()
    assert "## Feedback (lesson signals)" in text
    assert "| Class | Kind | Source | Count |" in text
    assert f"| {WEB} | poc_not_reproduced | learned | 2 |" in text
    assert f"| {WEB} | disproved | imported | 1 |" in text
    # Kind ids only, never the templates.
    for template in feedback.KINDS.values():
        assert template not in text


def test_report_has_no_feedback_heading_without_signals(ctx: RunContext):
    report.run_task(ctx, {})
    text = (ctx.out_dir / "REPORT.md").read_text()
    assert "Feedback (lesson signals)" not in text
