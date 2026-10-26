"""Held-out evaluation of the feedback loop.

Cloudflare's discipline for prompt changes: "whenever we update an underlying
prompt, we test it against a held-out repository to see if that total coverage
cell number actually moves." A lesson that only helps on the code it was learned
from is overfitting, not sharpening. This module runs that test.

Two comparison modes (``compare=``):

* ``imported`` (default) — train on one benchmark with in-run feedback on and
  the two ground-truth signals recorded, export the lessons it learned (only
  ``(attack_class, kind, count)``, never text), then run the *held-out*
  benchmark twice: **baseline** (arm A, no lessons) and **with lessons** (arm B,
  the exported file imported into every target's run). Both arms use the same
  adapters, sandbox, effort and in-run feedback setting (off by default), so the
  only difference between them is the imported lessons.
* ``in-run`` — no training and no imports. Arm A runs the held-out benchmark
  with in-run feedback off, arm B with it on, so the only difference is whether
  lessons learned during the run reach the hunts still in the queue.

Verdicts compare arm B with arm A, totals averaged over ``repeats``:

* ``incomplete`` — the spending cap was reached or a target was skipped in any
  phase; nothing else is claimed, because the arms did not run the same work.
* ``no change`` (zero lessons) — in ``imported`` mode, when training learned no
  lessons, both arms ran the same prompts, so any difference between them is
  noise; this is decided before any regression or win is considered.
* ``regressed`` — B's confirmed recall fell, or B confirmed more findings on
  decoys (false positives).
* ``improved`` — not regressed, and B raised confirmed recall, or covered more
  ``(area, attack_class)`` cells with confirmed findings, or had a lower
  rejection rate *while filing at least as many candidates*. A lower rejection
  rate earned by filing less is not a win.
* ``no change`` — otherwise, with the reason stated.

They are checked in that order: incomplete, zero lessons, regressed,
improved, no change.

The honesty rule: one run per arm is one sample, and real models are noisy. The
report says so plainly; ``repeats`` exists for when credit allows. Arm order
alternates per repeat (A first on odd repeats, B first on even) to spread any
drift, and the order run is recorded. One spending cap spans every phase.

This module builds no adapters of its own: ``benchmark.run_benchmark`` does,
through its module-level ``build_adapter``, which is also the test seam.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from . import benchmark, pricing
from . import feedback as feedback_mod
from .benchmark import BenchmarkSpec
from .db import Store
from .poc import tree_digest

COMPARE_MODES = ("imported", "in-run")

# The table rows, in order: (totals key, label, is a rate).
_METRICS: list[tuple[str, str, bool]] = [
    ("confirmed_recall", "Confirmed recall", True),
    ("recall", "Recall", True),
    ("false_positives", "False positives (confirmed on a decoy)", False),
    ("rejection_rate", "Validation rejection rate", True),
    ("candidates_total", "Candidates filed", False),
    ("cells_covered", "Coverage cells (confirmed, non-decoy)", False),
]
_LABELS = {k: label for k, label, _ in _METRICS}


@dataclass
class EvalReport:
    verdict: str                      # improved | no change | regressed | incomplete
    verdict_reason: str
    compare: str                      # imported | in-run
    train_totals: dict[str, Any] | None
    baseline_totals: dict[str, Any]   # arm A, averaged over repeats
    lessons_totals: dict[str, Any]    # arm B, averaged over repeats
    lessons: dict[str, Any] | None    # the exported lessons file (imported mode)
    repeats: int
    arm_order: list[str] = field(default_factory=list)
    cost_usd: float = 0.0
    incomplete_reasons: list[str] = field(default_factory=list)


def check_disjoint(train: BenchmarkSpec, holdout: BenchmarkSpec) -> None:
    """Refuse a held-out benchmark that shares a target with the training one,
    by name, by source content (``poc.tree_digest``, so a renamed copy is caught
    too), or by one target's directory lying inside the other's (the outer one
    would train on, or be tested on, the inner one's code). Training on a
    held-out target would make the test meaningless.

    A missing or empty target directory is refused first, with its own message:
    every empty tree has the same digest, so two of them would otherwise be
    reported as "the same source", which is true but sends the reader the
    wrong way."""
    def _dirs(spec: BenchmarkSpec, role: str) -> dict[str, Path]:
        out: dict[str, Path] = {}
        for t in spec.targets:
            d = (spec.base_dir / t.path).resolve()
            if not d.is_dir() or not any(d.iterdir()):
                raise ValueError(f"{role} target {t.name!r}: directory {d} is missing or empty")
            out[t.name] = d
        return out

    train_dirs = _dirs(train, "training")
    hold_dirs = _dirs(holdout, "held-out")
    train_digests = {tree_digest(d): name for name, d in train_dirs.items()}
    for name, d in hold_dirs.items():
        if name in train_dirs:
            raise ValueError(f"held-out target {name!r} is also a training target "
                             "(same name); the held-out set must be disjoint from training")
        for tname, td in train_dirs.items():
            if d.is_relative_to(td) or td.is_relative_to(d):
                raise ValueError(f"held-out target {name!r} ({d}) and training target "
                                 f"{tname!r} ({td}) overlap: one directory is inside the "
                                 "other; the held-out set must be disjoint from training")
        digest = tree_digest(d)
        if digest in train_digests:
            raise ValueError(f"held-out target {name!r} has the same source as training "
                             f"target {train_digests[digest]!r}; the held-out set must be "
                             "disjoint from training")


def run_feedback_eval(holdout_spec: BenchmarkSpec, *, train_spec: BenchmarkSpec | None = None,
                      compare: str = "imported", finder_spec: str,
                      validator_spec: str | None, sandbox_kind: str, out_dir: Path,
                      effort: str | None = None, max_cost: float | None = None,
                      repeats: int = 1, in_run_feedback: bool = False,
                      min_count: int = 1) -> EvalReport:
    """Train (imported mode), export lessons, run both held-out arms, judge.

    Every refusal (bad mode, missing or unwanted ``train_spec``, overlapping
    targets, ``repeats`` below 1) is raised before any directory is created or
    any model is called."""
    if compare not in COMPARE_MODES:
        raise ValueError(f"compare must be one of {', '.join(COMPARE_MODES)}, got {compare!r}")
    if compare == "imported" and train_spec is None:
        raise ValueError("compare 'imported' needs a training benchmark (--train) to learn "
                         "lessons from")
    if compare == "in-run" and train_spec is not None:
        raise ValueError("compare 'in-run' does not train; drop --train (it would be ignored)")
    if repeats < 1:
        raise ValueError(f"repeats must be at least 1, got {repeats}")
    if train_spec is not None:
        check_disjoint(train_spec, holdout_spec)

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    budget = pricing.Budget(max_cost) if max_cost is not None else None
    common: dict[str, Any] = {"finder_spec": finder_spec, "validator_spec": validator_spec,
                              "sandbox_kind": sandbox_kind, "effort": effort,
                              "budget": budget}
    phases: list[tuple[str, benchmark.BenchmarkReport]] = []

    train_totals: dict[str, Any] | None = None
    lessons: dict[str, Any] | None = None
    if train_spec is not None:
        train = benchmark.run_benchmark(train_spec, out_dir=out_dir / "train", feedback=True,
                                        record_training_signals=True, **common)
        phases.append(("train", train))
        train_totals = train.totals
        store = Store(out_dir / "train" / "benchmark.sqlite")
        try:
            lessons = feedback_mod.export_lessons(store, train.totals["run_ids"],
                                                  min_count=min_count)
        finally:
            store.close()
        # Written before the held-out phase, so nothing held-out can reach it.
        (out_dir / "lessons.json").write_text(json.dumps(lessons, indent=2) + "\n")

    def _arm(arm: str, r: int) -> benchmark.BenchmarkReport:
        if compare == "in-run":
            kw: dict[str, Any] = {"feedback": arm == "lessons", "lessons": None}
        else:
            kw = {"feedback": in_run_feedback,
                  "lessons": lessons if arm == "lessons" else None}
        return benchmark.run_benchmark(holdout_spec, out_dir=out_dir / f"holdout-{arm}-{r}",
                                       **kw, **common)

    arm_order: list[str] = []
    by_arm: dict[str, list[dict[str, Any]]] = {"baseline": [], "lessons": []}
    for r in range(1, repeats + 1):
        order = ("baseline", "lessons") if r % 2 else ("lessons", "baseline")
        for arm in order:
            rep = _arm(arm, r)
            label = f"{arm}-{r}"
            arm_order.append(label)
            phases.append((f"holdout-{label}", rep))
            by_arm[arm].append(rep.totals)

    a, b = _average(by_arm["baseline"]), _average(by_arm["lessons"])
    reasons = _incomplete_reasons(phases)
    verdict, why = _verdict(a, b, reasons, compare=compare, lessons=lessons)
    cost = round(sum(p.totals.get("estimated_cost_usd", 0.0) for _, p in phases), 4)

    report = EvalReport(verdict=verdict, verdict_reason=why, compare=compare,
                        train_totals=train_totals, baseline_totals=a, lessons_totals=b,
                        lessons=lessons, repeats=repeats, arm_order=arm_order,
                        cost_usd=cost, incomplete_reasons=reasons)
    first = phases[0][1]
    _write(report, out_dir, holdout=holdout_spec, train=train_spec, finder=first.finder,
           validator=first.validator, max_cost=max_cost, in_run_feedback=in_run_feedback,
           fully_priced=all(p.totals.get("cost_fully_priced", True) for _, p in phases))
    return report


# ---- judging -------------------------------------------------------------

def _average(runs: list[dict[str, Any]]) -> dict[str, Any]:
    """Mean of every numeric total across one arm's runs (booleans, lists and
    ``None`` are not averaged)."""
    out: dict[str, Any] = {}
    for key in runs[0]:
        vals = [r.get(key) for r in runs]
        if all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in vals):
            out[key] = round(sum(vals) / len(vals), 4)  # type: ignore[arg-type]
    return out


def _incomplete_reasons(phases: list[tuple[str, benchmark.BenchmarkReport]]) -> list[str]:
    reasons: list[str] = []
    for name, rep in phases:
        t = rep.totals
        if t.get("cap_reached"):
            reasons.append(f"{name}: spending cap reached")
        if t.get("skipped_targets"):
            reasons.append(f"{name}: skipped {', '.join(t['skipped_targets'])}")
    return reasons


def _fmt(key: str, value: float) -> str:
    rate = next(r for k, _, r in _METRICS if k == key)
    return f"{value:.0%}" if rate else f"{value:g}"


def _verdict(a: dict[str, Any], b: dict[str, Any], incomplete: list[str], *,
             compare: str, lessons: dict[str, Any] | None) -> tuple[str, str]:
    """The verdict and its reason, per the rules in the module docstring."""
    if incomplete:
        return "incomplete", ("the arms did not run the same work, so nothing is claimed ("
                              + "; ".join(incomplete) + ")")
    # With nothing learned, both arms ran identical prompts: any difference,
    # better or worse, is the model's own noise, so neither a win nor a
    # regression is claimed.
    if compare == "imported" and lessons is not None and not lessons["lessons"]:
        return "no change", ("no lessons were learned in training, so both arms ran the same "
                             "prompts; any difference is noise")

    def moved(key: str, verb: str) -> str:
        return f"{_LABELS[key].lower()} {verb} from {_fmt(key, a[key])} to {_fmt(key, b[key])}"

    regressions = []
    if b["confirmed_recall"] < a["confirmed_recall"]:
        regressions.append(moved("confirmed_recall", "fell"))
    if b["false_positives"] > a["false_positives"]:
        regressions.append(moved("false_positives", "rose"))
    if regressions:
        return "regressed", "; ".join(regressions)

    wins = []
    if b["confirmed_recall"] > a["confirmed_recall"]:
        wins.append(moved("confirmed_recall", "rose"))
    if b["cells_covered"] > a["cells_covered"]:
        wins.append(moved("cells_covered", "rose"))
    caveat = ""
    if b["rejection_rate"] < a["rejection_rate"]:
        if b["candidates_total"] >= a["candidates_total"]:
            wins.append(moved("rejection_rate", "fell") + " with "
                        + f"{_fmt('candidates_total', b['candidates_total'])} candidates filed "
                        + f"(baseline {_fmt('candidates_total', a['candidates_total'])})")
        else:
            caveat = (f"the rejection rate fell only because arm B filed fewer candidates "
                      f"({_fmt('candidates_total', b['candidates_total'])} vs "
                      f"{_fmt('candidates_total', a['candidates_total'])}), which is not a win")
    if wins:
        return "improved", "; ".join(wins)
    if caveat:
        return "no change", caveat
    moves = [moved(k, "rose" if b[k] > a[k] else "fell")
             for k in ("confirmed_recall", "false_positives", "rejection_rate", "cells_covered")
             if b[k] != a[k]]
    if not moves:
        return "no change", ("confirmed recall, false positives, rejection rate and coverage "
                             "cells were the same in both arms")
    return "no change", "nothing moved in a way that counts as a win: " + "; ".join(moves)



# ---- writing -------------------------------------------------------------

def _write(report: EvalReport, out_dir: Path, *, holdout: BenchmarkSpec,
           train: BenchmarkSpec | None, finder: str, validator: str,
           max_cost: float | None, in_run_feedback: bool, fully_priced: bool) -> None:
    data = {"holdout": holdout.name, "train": train.name if train else None,
            "finder": finder, "validator": validator, "max_cost_usd": max_cost,
            "in_run_feedback": in_run_feedback if report.compare == "imported" else None,
            **asdict(report)}
    (out_dir / "feedback-eval.json").write_text(json.dumps(data, indent=2) + "\n")
    (out_dir / "feedback-eval.md").write_text(
        "\n".join(_markdown(report, holdout=holdout, train=train, finder=finder,
                            validator=validator, max_cost=max_cost,
                            in_run_feedback=in_run_feedback, fully_priced=fully_priced)) + "\n")


def _markdown(report: EvalReport, *, holdout: BenchmarkSpec, train: BenchmarkSpec | None,
              finder: str, validator: str, max_cost: float | None,
              in_run_feedback: bool, fully_priced: bool) -> list[str]:
    a, b = report.baseline_totals, report.lessons_totals
    arm_b = "With lessons" if report.compare == "imported" else "With in-run feedback"
    if report.compare == "imported":
        mode = (f"Mode: `imported`. Lessons were learned on `{train.name if train else '?'}` "
                f"and tested on `{holdout.name}`, which they were never trained on. Both arms "
                "ran with the same models, sandbox and settings (in-run feedback "
                f"{'on' if in_run_feedback else 'off'} in both); the only difference is the "
                "imported lessons.")
    else:
        mode = (f"Mode: `in-run`. No training. Both arms ran `{holdout.name}`; the baseline "
                "with in-run feedback off and the other arm with it on, so the only difference "
                "is whether lessons learned during the run reached the hunts still queued.")
    runs = "run" if report.repeats == 1 else "runs"
    lines = [
        f"# Feedback eval — {holdout.name}",
        "",
        f"**Verdict: {report.verdict}** — {report.verdict_reason}.",
        "",
        mode,
        "",
        f"- Finder: `{finder}`  ·  Validator: `{validator}`",
        (f"- Held-out targets: {len(holdout.targets)} "
         f"({sum(1 for t in holdout.targets if t.decoy)} decoys)"),
        f"- Arm order: {', '.join(report.arm_order)}",
        "",
        f"## Held-out results (mean of {report.repeats} {runs} per arm)",
        "",
        f"| Metric | Baseline | {arm_b} | Δ |",
        "| --- | --- | --- | --- |",
    ]
    for key, label, rate in _METRICS:
        va, vb = a.get(key, 0.0), b.get(key, 0.0)
        delta = vb - va
        if rate:
            d = f"{delta * 100:+.0f} pts" if delta else "0"
        else:
            d = f"{delta:+g}" if delta else "0"
        lines.append(f"| {label} | {_fmt(key, va)} | {_fmt(key, vb)} | {d} |")
    lines += ["", _sample_sentence(report.repeats)]
    if report.incomplete_reasons:
        lines += ["", "**Incomplete:** " + "; ".join(report.incomplete_reasons) + "."]

    lines += ["", "## Lessons", ""]
    if report.compare == "in-run":
        lines.append("None imported: this mode compares in-run feedback off and on.")
    elif not report.lessons or not report.lessons["lessons"]:
        lines.append("No lessons were learned in training, so both arms ran the same prompts.")
    else:
        rows = report.lessons["lessons"]
        noun = "lesson" if len(rows) == 1 else "lessons"
        lines += [(f"{len(rows)} {noun} learned in training and imported into the "
                   "with-lessons arm (`lessons.json`):"), "",
                  "| Class | Kind | Count |", "| --- | --- | --- |"]
        lines += [f"| {r['attack_class']} | {r['kind']} | {r['count']} |" for r in rows]
        lines += ["", "What each kind tells the hunter, as it appears in the prompt:", ""]
        for kind in sorted({r["kind"] for r in rows}):
            lines.append(f"- `{kind}`: {feedback_mod.KINDS[kind]}")

    cap = f" (cap ${max_cost:.2f})" if max_cost is not None else ""
    priced = "" if fully_priced else " (some models unpriced)"
    lines += ["", "## Cost", "",
              f"- Estimated cost, every phase together: ${report.cost_usd:.4f}{priced}{cap}"]

    if report.train_totals is not None and train is not None:
        t = report.train_totals
        lines += ["", "## Training run", "",
                  (f"- Benchmark: `{train.name}` ({len(train.targets)} targets), in-run "
                   "feedback on, ground-truth signals recorded"),
                  (f"- Recall: {t['recall']:.0%}  ·  Confirmed recall: "
                   f"{t['confirmed_recall']:.0%}  ·  Rejection rate: {t['rejection_rate']:.0%} "
                   f"({t['rejected']}/{t['candidates_total']})"),
                  (f"- False positives: {t['false_positives']}  ·  Coverage cells: "
                   f"{t.get('cells_covered', 0)}"),
                  "- Full report: `train/benchmark-report.md`"]
    return lines


def _sample_sentence(repeats: int) -> str:
    if repeats == 1:
        return ("1 run per arm: a single sample, and real models are noisy. Treat a small "
                "difference as noise until repeats confirm it.")
    return (f"{repeats} runs per arm, averaged. Real models are noisy, so a small difference "
            "can still be chance.")
