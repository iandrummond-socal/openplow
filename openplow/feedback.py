"""Feedback loop — typed lesson signals that sharpen hunts still in the queue.

Every failure the pipeline already detects (a PoC that does not reproduce, a
tampering PoC, a reply that cannot be parsed, a patch that fails the fix gate,
...) is recorded as a **lesson signal**: a count of one *kind* of failure for
one attack class, kept in the store's ``lessons`` table. Hunt prompts are built
when a hunt task is claimed, not when it is queued, so every hunt still waiting
picks up the lessons learned so far. That is "rewriting queued prompts", and it
is crash-safe and resumable because the counts live in SQLite.

Why the kinds are a closed set with fixed templates, and carry no text:

- **No answer leakage.** A lesson is only ``(attack_class, kind, count)``. A
  lessons file exported from a training benchmark therefore has nowhere to put
  a file name, a symbol or a finding title, so it can never smuggle the answer
  to a benchmark into a prompt. ``check_lessons`` refuses any other field.
- **Deterministic and diff-able.** Each kind renders from one template here, so
  the same signals always give byte-identical prompt text, tests can pin it, and
  an exported file sorts the same way every time.
- **Free.** No model writes prompt text in this version. A model-written
  rewriter is a later step, and ``feedback_eval`` is the gate it must pass.

Why lessons go in the *user* prompt: the hunter's system prompt (the class
methodology) is the cached prefix. Lessons change during a run, and putting
them in the system prompt would break the cache for every hunt.

Deliberately **not** kinds:

- a *refusal* — guidance aimed at getting past a safety classifier would be
  evasion, not sharpening, so refusals stay on the wishlist for a person;
- a *shallow* hunt with zero findings — most cells are legitimately empty, and
  gapfill already re-hunts thin cells deeper.

A known, accepted overcount: a task left ``running`` by a crash is requeued on
resume and re-records any signal it wrote before the crash. Counts only order
and cap the lessons, so the effect is a slightly heavier weight on one kind,
which is not worth per-task bookkeeping.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .context import RunContext
from .db import Store

# The closed vocabulary: kind -> the one bullet it renders as.
KINDS: dict[str, str] = {
    "poc_not_reproduced": (
        "Earlier PoCs in this class did not reproduce. A test or script PoC runs with python3 "
        "from the repo root against the untouched code; it must exit 0 and print its exact "
        "`observed` marker, and must not rely on files, services or state it does not create "
        "itself."
    ),
    "poc_tampered": (
        "Earlier PoCs edited existing source and were rejected. A PoC may create new files, "
        "but must never modify, delete or overwrite a file that already exists in the repo."
    ),
    "poc_timeout": (
        "Earlier PoCs timed out. Keep PoCs small and fast: bounded inputs, no sleeps, no "
        "unbounded loops; show a resource blow-up with a measured, capped input."
    ),
    "poc_not_executable": (
        "Earlier findings used input or trace PoCs, which cannot confirm a bug or verify a "
        "patch. Use a test or script PoC whenever the issue can be shown in Python."
    ),
    "disproved": (
        "The validator disproved earlier findings in this class, usually because another layer "
        "already blocks the attack. Before filing, name the defence you looked for and show why "
        "it does not stop the attacker."
    ),
    "incomplete_finding": (
        "Earlier findings were dropped or rejected for missing parts. Every finding needs an "
        "attacker and a boundary, a location in a file that exists, and a PoC."
    ),
    "unparseable": (
        "Earlier replies could not be parsed. Return exactly one ```json fenced array of "
        "findings and nothing after it."
    ),
    "truncated": (
        "Earlier replies were cut off at the output limit. File fewer, stronger findings and "
        "keep each description short."
    ),
    "patch_failed": (
        "Earlier patches did not apply or did not stop the PoC. Copy hunk context lines exactly "
        "from the file you read, and make sure the patched code would stop your own PoC "
        "printing its marker."
    ),
    "missed_known": (
        "On reference audits, real bugs in this class were missed. Trace every "
        "attacker-controlled input in this area to each sink this class covers before "
        "concluding there is nothing."
    ),
    "false_positive": (
        "On reference audits, findings in this class were confirmed on code with no bug. File "
        "only when the PoC demonstrates a real boundary failure, not a pattern that merely "
        "looks risky."
    ),
}

# About reply shape, not the class: a hunt of any class gets these once any
# class has recorded them.
GENERIC_KINDS = frozenset({"unparseable", "truncated", "incomplete_finding"})

# Need ground truth, so only a training benchmark writes them — never a plain run.
TRAINING_KINDS = frozenset({"missed_known", "false_positive"})

MAX_LESSONS = 6
LESSONS_VERSION = 1

_HEADING = "# Lessons from earlier tasks"
_INTRO = "These come from failures earlier in this audit (or from earlier audits). Apply them."

_ROW_KEYS = {"attack_class", "kind", "count"}
_TOP_KEYS = {"version", "lessons"}


def _attack_classes() -> set[str]:
    # Imported lazily: openplow.stages imports every stage, and the stages
    # import this module, so a top-level import of stages.recon would cycle.
    from .stages.recon import ATTACK_CLASSES

    return set(ATTACK_CLASSES)


def record(ctx: RunContext, attack_class: str, kind: str, n: int = 1) -> None:
    """Record ``n`` signals of ``kind`` for ``attack_class`` in this run.

    An unknown kind is a programming error and raises. A class outside
    ``ATTACK_CLASSES`` (hunt payloads default to ``"unknown"``) is skipped
    silently: a lessons file would refuse such a row, and every caller goes
    through here so no stage needs its own class check.
    """
    if kind not in KINDS:
        raise ValueError(f"unknown lesson kind {kind!r}")
    if attack_class not in _attack_classes():
        return
    ctx.store.add_lesson_signal(ctx.run_id, attack_class, kind, source="learned", n=n)


def lessons_for(ctx: RunContext, attack_class: str) -> list[str]:
    """The lesson kinds a hunt of ``attack_class`` should carry, most-seen first.

    Class-specific kinds count only for their own class; generic kinds count
    from any class. Learned and imported counts are summed per kind. Learned
    signals are used only when ``ctx.feedback`` is on; imported ones always.
    """
    sources: tuple[str, ...] = ("learned", "imported") if ctx.feedback else ("imported",)
    totals: dict[str, int] = {}
    for row in ctx.store.lesson_signals(ctx.run_id, sources=sources):
        kind = row["kind"]
        if kind not in KINDS or row["count"] <= 0:
            continue
        if kind in GENERIC_KINDS or row["attack_class"] == attack_class:
            totals[kind] = totals.get(kind, 0) + row["count"]
    ordered = sorted(totals, key=lambda k: (-totals[k], k))
    return ordered[:MAX_LESSONS]


def render(kinds: list[str]) -> str:
    """The prompt section for ``kinds``, or ``""`` so a prompt with no lessons
    stays byte-identical to one built before the feedback loop existed."""
    if not kinds:
        return ""
    lines = [_HEADING, _INTRO] + [f"- {KINDS[k]}" for k in kinds]
    return "\n".join(lines)


def export_lessons(store: Store, run_ids: list[str], *, min_count: int = 1) -> dict[str, Any]:
    """Sum signals across ``run_ids`` (both sources) into a version-1 lessons file.

    Rows of an unknown class or kind are dropped — benchmark training signals
    write through the store directly, so this is the belt to ``record``'s
    braces — and the output is sorted, so an exported file always passes
    ``check_lessons`` and diffs cleanly.
    """
    classes = _attack_classes()
    totals: dict[tuple[str, str], int] = {}
    for run_id in run_ids:
        for row in store.lesson_signals(run_id):
            key = (row["attack_class"], row["kind"])
            if key[0] not in classes or key[1] not in KINDS:
                continue
            totals[key] = totals.get(key, 0) + row["count"]
    floor = max(min_count, 1)
    lessons = [
        {"attack_class": cls, "kind": kind, "count": count}
        for (cls, kind), count in sorted(totals.items())
        if count >= floor
    ]
    return {"version": LESSONS_VERSION, "lessons": lessons}


def check_lessons(data: Any) -> dict[str, Any]:
    """Strictly validate a lessons file and return a clean copy.

    The strictness is the leakage guard: a row holds only a known class, a
    known kind and a positive count, so there is nowhere to put text.
    """
    if not isinstance(data, dict):
        raise ValueError("lessons file must be a JSON object")  # noqa: TRY004 - CLI refusal
    extra = set(data) - _TOP_KEYS
    if extra:
        raise ValueError(f"lessons file has unknown top-level key(s): {', '.join(sorted(extra))}")
    version = data.get("version")
    if isinstance(version, bool) or version != LESSONS_VERSION:
        raise ValueError(f"lessons file version must be {LESSONS_VERSION}, got {version!r}")
    rows = data.get("lessons")
    if not isinstance(rows, list):
        raise ValueError("lessons file 'lessons' must be a list")  # noqa: TRY004 - CLI refusal
    classes = _attack_classes()
    seen: set[tuple[str, str]] = set()
    clean: list[dict[str, Any]] = []
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"lesson {i} must be an object")  # noqa: TRY004 - CLI refusal
        extra = set(row) - _ROW_KEYS
        if extra:
            raise ValueError(f"lesson {i} has unknown field(s): {', '.join(sorted(extra))}")
        missing = _ROW_KEYS - set(row)
        if missing:
            raise ValueError(f"lesson {i} is missing field(s): {', '.join(sorted(missing))}")
        cls, kind, count = row["attack_class"], row["kind"], row["count"]
        if cls not in classes:
            raise ValueError(f"lesson {i} has unknown attack class {cls!r}")
        if kind not in KINDS:
            raise ValueError(f"lesson {i} has unknown kind {kind!r}")
        if isinstance(count, bool) or not isinstance(count, int) or count < 1:
            raise ValueError(f"lesson {i} count must be a positive integer, got {count!r}")
        if (cls, kind) in seen:
            raise ValueError(f"lesson {i} repeats {cls}/{kind}")
        seen.add((cls, kind))
        clean.append({"attack_class": cls, "kind": kind, "count": count})
    return {"version": LESSONS_VERSION, "lessons": clean}


def load_lessons(path: str | Path) -> dict[str, Any]:
    """Read and strictly validate a lessons file."""
    try:
        data = json.loads(Path(path).read_text())
    except json.JSONDecodeError as e:
        raise ValueError(f"lessons file {path} is not valid JSON: {e}") from e
    return check_lessons(data)


def import_lessons(store: Store, run_id: str, data: dict[str, Any]) -> int:
    """Write a lessons file into ``run_id`` as ``imported`` rows; return rows written.

    Counts are *set*, not added, so importing the same file again (say on
    ``openplow run --resume X --lessons f``) leaves every count unchanged.
    """
    clean = check_lessons(data)
    for row in clean["lessons"]:
        store.set_lesson_signal(run_id, row["attack_class"], row["kind"],
                                source="imported", count=row["count"])
    return len(clean["lessons"])


def summary(store: Store, run_id: str) -> list[dict[str, Any]]:
    """Every ``(attack_class, kind, source, count)`` row of a run, for the report."""
    return [
        {"attack_class": r["attack_class"], "kind": r["kind"],
         "source": r["source"], "count": r["count"]}
        for r in store.lesson_signals(run_id)
    ]
