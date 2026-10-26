"""OpenPlow command-line interface.

    openplow run <repo> [--adapter stub] [--validator-adapter ...] [--resume ID]
                 [--lessons FILE] [--no-feedback]
    openplow benchmark <spec> [--adapter ...] [--lessons FILE] [--no-feedback]
                 [--record-training-signals] [--export-lessons FILE]
    openplow rescore <run-dir> --spec <spec>
    openplow feedback-eval <holdout-spec> --train <spec> [--compare imported|in-run]
                 [--adapter ...] [--max-cost USD] [--repeats N]
    openplow status <run-id>
    openplow findings <run-id> [--verdict confirmed]
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path

from . import __version__
from .context import RunContext
from .db import Store
from .models import MeteredAdapter, build_adapter
from .orchestrator import start_run
from .sandbox import build_sandbox

DEFAULT_RUNS_DIR = Path("openplow-runs")
DEFAULT_DB = DEFAULT_RUNS_DIR / "openplow.sqlite"


def _store() -> Store:
    DEFAULT_RUNS_DIR.mkdir(parents=True, exist_ok=True)
    return Store(DEFAULT_DB)


def cmd_run(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    if not repo.is_dir():
        print(f"error: target repo not found: {repo}", file=sys.stderr)
        return 2

    lessons = None
    if args.lessons:
        from .feedback import load_lessons
        try:
            lessons = load_lessons(args.lessons)
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    run_id = args.resume or f"run-{uuid.uuid4().hex[:12]}"
    out_dir = DEFAULT_RUNS_DIR / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    store = _store()
    from .pricing import Budget
    budget = Budget(args.max_cost) if args.max_cost is not None else None
    # The validator must be a DIFFERENT model from the finder in real runs; for
    # the stub they are the same no-op adapter. Both are metered for cost.
    finder = MeteredAdapter(build_adapter(args.adapter, effort=args.effort, budget=budget),
                            store, run_id, repo.name, "finder")
    validator = MeteredAdapter(build_adapter(args.validator_adapter or args.adapter,
                                             effort=args.effort, budget=budget),
                               store, run_id, repo.name, "validator")
    sandbox = build_sandbox(args.sandbox, out_dir / "scratch")

    ctx = RunContext(run_id=run_id, repo=repo, out_dir=out_dir, store=store,
                     finder=finder, validator=validator, sandbox=sandbox,
                     feedback=not args.no_feedback)
    if lessons is not None:
        from .feedback import import_lessons
        # Counts are set, not added, so --resume with the same file is idempotent.
        import_lessons(store, run_id, lessons)

    print(f"OpenPlow {__version__}  run={run_id}  repo={repo.name}  "
          f"finder={finder.name}  validator={validator.name}")
    summary = start_run(ctx, resume=bool(args.resume))
    print(f"done: processed={summary.processed} failed={summary.failed}")
    if summary.final:
        print(f"confirmed={summary.final.get('confirmed')} "
              f"fix_verified={summary.final.get('fix_verified')} "
              f"needs_validation={summary.final.get('needs_validation')} "
              f"rejected={summary.final.get('rejected')}")
    _print_cost(store, run_id)
    if budget is not None and budget.exhausted:
        print(f"spending cap ${budget.limit:.2f} reached; the run stopped making model "
              "calls and its results are incomplete")
    print(f"artifacts: {out_dir}")
    store.close()
    return 1 if summary.failed else 0


def _print_cost(store: Store, run_id: str) -> None:
    from .pricing import Usage, estimate_cost
    rows = store.usage_by_model(run_id)
    if not rows:
        return
    total = 0.0
    priced = True
    for r in rows:
        u = Usage(r["input_tokens"], r["output_tokens"], r["cache_read"], r["cache_creation"])
        c = estimate_cost(r["model"], u)
        if c is None:
            priced = False
        else:
            total += c
    note = "" if priced else " (some models unpriced)"
    print(f"estimated cost: ${total:.4f}{note}")


def cmd_benchmark(args: argparse.Namespace) -> int:
    from .benchmark import load_spec, run_benchmark

    try:
        spec = load_spec(args.spec)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    lessons = None
    if args.lessons:
        from .feedback import load_lessons
        try:
            lessons = load_lessons(args.lessons)
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    out_dir = Path(args.out).resolve()
    print(f"OpenPlow benchmark '{spec.name}'  targets={len(spec.targets)}  "
          f"finder={args.adapter}  validator={args.validator_adapter or args.adapter}")
    report = run_benchmark(spec, finder_spec=args.adapter,
                           validator_spec=args.validator_adapter,
                           sandbox_kind=args.sandbox, out_dir=out_dir, effort=args.effort,
                           max_cost=args.max_cost, feedback=not args.no_feedback,
                           lessons=lessons,
                           record_training_signals=args.record_training_signals)
    t = report.totals
    print(f"recall={t['recall']:.0%} confirmed_recall={t['confirmed_recall']:.0%} "
          f"rejection_rate={t['rejection_rate']:.0%} "
          f"unmatched_confirmed={t['unmatched_confirmed']}"
          + (f" decoys_clean={t['decoys_clean']}/{t['decoy_targets']} "
             f"false_positives={t['false_positives']}" if t.get("decoy_targets") else ""))
    cost_note = "" if t.get("cost_fully_priced", True) else " (some models unpriced)"
    print(f"estimated cost: ${t.get('estimated_cost_usd', 0.0):.4f}{cost_note}")
    if t.get("cap_reached"):
        skipped = ", ".join(t.get("skipped_targets") or []) or "none"
        print(f"spending cap ${t['max_cost_usd']:.2f} reached; results are incomplete "
              f"(skipped targets: {skipped})")
    if args.export_lessons:
        from .feedback import export_lessons
        store = Store(out_dir / "benchmark.sqlite")
        try:
            exported = export_lessons(store, t["run_ids"])
        finally:
            store.close()
        dest = Path(args.export_lessons)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(exported, indent=2) + "\n")
        print(f"lessons: {len(exported['lessons'])} exported to {dest}")
    print(f"report: {out_dir / 'benchmark-report.md'}")
    return 0


def cmd_feedback_eval(args: argparse.Namespace) -> int:
    from .benchmark import load_spec
    from .feedback_eval import run_feedback_eval

    paid = [a for a in (args.adapter, args.validator_adapter) if a and a.startswith("anthropic:")]
    if paid and args.max_cost is None:
        print("error: feedback-eval runs several benchmarks; set --max-cost", file=sys.stderr)
        return 2
    out_dir = Path(args.out).resolve()
    try:
        holdout = load_spec(args.holdout)
        train = load_spec(args.train) if args.train else None
        print(f"OpenPlow feedback-eval  holdout='{holdout.name}'  "
              f"train={repr(train.name) if train else 'none'}  compare={args.compare}  "
              f"finder={args.adapter}  validator={args.validator_adapter or args.adapter}")
        report = run_feedback_eval(holdout, train_spec=train, compare=args.compare,
                                   finder_spec=args.adapter,
                                   validator_spec=args.validator_adapter,
                                   sandbox_kind=args.sandbox, out_dir=out_dir,
                                   effort=args.effort, max_cost=args.max_cost,
                                   repeats=args.repeats, in_run_feedback=args.in_run_feedback,
                                   min_count=args.min_count)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"verdict: {report.verdict}")
    print(f"reason: {report.verdict_reason}")
    print(f"estimated cost: ${report.cost_usd:.4f}")
    print(f"report: {out_dir / 'feedback-eval.md'}")
    return 1 if report.verdict == "regressed" else 0


def _at_least_one(text: str) -> int:
    n = int(text)
    if n < 1:
        raise argparse.ArgumentTypeError(f"must be at least 1, got {n}")
    return n


def cmd_rescore(args: argparse.Namespace) -> int:
    from .benchmark import load_spec
    from .rescore import rescore

    out_dir = Path(args.out).resolve() if args.out else None
    try:
        spec = load_spec(args.spec)
        report = rescore(Path(args.run_dir), spec, out_dir,
                         rerun_fix_gate=args.rerun_fix_gate, sandbox_kind=args.sandbox,
                         assume_targets_unchanged=args.assume_targets_unchanged)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    t = report.totals
    print(f"recall={t['recall']:.0%} confirmed_recall={t['confirmed_recall']:.0%} "
          f"rejection_rate={t['rejection_rate']:.0%} "
          f"unmatched_confirmed={t['unmatched_confirmed']} "
          f"duplicates_folded={t['duplicates_folded']} fix_verified={t['fix_verified']}"
          + (f" decoys_clean={t['decoys_clean']}/{t['decoy_targets']} "
             f"false_positives={t['false_positives']}" if t.get("decoy_targets") else ""))
    if t["targets_not_in_run"]:
        print(f"not in this run (not scored): {', '.join(t['targets_not_in_run'])}")
    if t.get("fix_gate_rerun"):
        print(f"fix gate re-run on {t['fix_gate_run']} finding(s); "
              f"{t['fix_gate_changed']} changed result")
    print(f"report: {(out_dir or Path(args.run_dir).resolve() / 'rescore') / 'benchmark-report.md'}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    store = _store()
    run = store.get_run(args.run_id)
    if not run:
        print(f"no such run: {args.run_id}", file=sys.stderr)
        return 2
    counts = store.task_counts(args.run_id)
    print(json.dumps({"run": run, "tasks": counts}, indent=2))
    store.close()
    return 0


def cmd_findings(args: argparse.Namespace) -> int:
    store = _store()
    findings = store.findings(args.run_id, verdict=args.verdict)
    print(json.dumps(findings, indent=2))
    store.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="openplow", description=__doc__)
    p.add_argument("--version", action="version", version=f"openplow {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="run the pipeline against a target repo")
    run.add_argument("repo", help="path to the target checkout")
    run.add_argument("--adapter", default="stub",
                     help="finder model adapter (e.g. stub, anthropic:<model-id>)")
    run.add_argument("--validator-adapter", default=None,
                     help="validator model adapter; defaults to --adapter")
    run.add_argument("--sandbox", default="stub", choices=["stub", "unshare"])
    run.add_argument("--effort", default="high",
                     choices=["low", "medium", "high", "xhigh", "max"],
                     help="model effort for Anthropic adapters (default high)")
    run.add_argument("--max-cost", type=float, default=None, metavar="USD",
                     help="stop making model calls once estimated spend reaches this")
    run.add_argument("--resume", default=None, metavar="RUN_ID",
                     help="resume an interrupted run")
    run.add_argument("--lessons", default=None, metavar="FILE",
                     help="import a lessons file (from benchmark --export-lessons)")
    run.add_argument("--no-feedback", action="store_true",
                     help="do not put lessons learned in this run into later hunt prompts "
                          "(imported lessons still apply)")
    run.set_defaults(func=cmd_run)

    bm = sub.add_parser("benchmark", help="run the pipeline over a benchmark spec and score it")
    bm.add_argument("spec", help="path to a benchmark spec JSON")
    bm.add_argument("--adapter", default="stub", help="finder model adapter")
    bm.add_argument("--validator-adapter", default=None, help="validator adapter")
    bm.add_argument("--sandbox", default="stub", choices=["stub", "unshare"])
    bm.add_argument("--effort", default="high",
                    choices=["low", "medium", "high", "xhigh", "max"],
                    help="model effort for Anthropic adapters (default high)")
    bm.add_argument("--out", default="openplow-benchmarks", help="output directory")
    bm.add_argument("--max-cost", type=float, default=None, metavar="USD",
                    help="spending cap shared by all targets; later targets are skipped")
    bm.add_argument("--lessons", default=None, metavar="FILE",
                    help="import a lessons file into every target's run")
    bm.add_argument("--no-feedback", action="store_true",
                    help="do not put lessons learned in a run into its later hunt prompts")
    bm.add_argument("--record-training-signals", action="store_true",
                    help="record missed known vulns and decoy false positives as lessons "
                         "(training benchmarks only)")
    bm.add_argument("--export-lessons", default=None, metavar="FILE",
                    help="write the lessons from every target's run to FILE after the run")
    bm.set_defaults(func=cmd_benchmark)

    fe = sub.add_parser("feedback-eval",
                        help="test learned lessons on a held-out benchmark (baseline vs "
                             "with lessons) and give a verdict")
    fe.add_argument("holdout", help="the held-out benchmark spec (never trained on)")
    fe.add_argument("--train", default=None, metavar="SPEC",
                    help="training benchmark spec to learn lessons on (needed for "
                         "--compare imported)")
    fe.add_argument("--compare", default="imported", choices=["imported", "in-run"],
                    help="imported: baseline vs lessons learned on --train (default); "
                         "in-run: in-run feedback off vs on, no training")
    fe.add_argument("--adapter", default="stub", help="finder model adapter")
    fe.add_argument("--validator-adapter", default=None, help="validator adapter")
    fe.add_argument("--sandbox", default="stub", choices=["stub", "unshare"])
    fe.add_argument("--effort", default="high",
                    choices=["low", "medium", "high", "xhigh", "max"],
                    help="model effort for Anthropic adapters (default high)")
    fe.add_argument("--max-cost", type=float, default=None, metavar="USD",
                    help="one spending cap shared by every phase; required for anthropic: "
                         "adapters")
    fe.add_argument("--repeats", type=_at_least_one, default=1, metavar="N",
                    help="held-out runs per arm, averaged (default 1)")
    fe.add_argument("--in-run-feedback", action="store_true",
                    help="imported mode: let both held-out arms also use in-run lessons")
    fe.add_argument("--min-count", type=_at_least_one, default=1, metavar="N",
                    help="export only lessons seen at least N times in training (default 1)")
    fe.add_argument("--out", default="openplow-feedback-eval", help="output directory")
    fe.set_defaults(func=cmd_feedback_eval)

    rs = sub.add_parser("rescore", help="re-score a saved benchmark run with the current "
                                        "dedup and scoring rules (no model calls)")
    rs.add_argument("run_dir", help="a benchmark output directory (has bench-*/findings.json)")
    rs.add_argument("--spec", required=True, help="the benchmark spec the run used")
    rs.add_argument("--out", default=None, help="report directory (default: RUN_DIR/rescore)")
    rs.add_argument("--rerun-fix-gate", action="store_true",
                    help="run the fix gate again on confirmed findings with a patch (runs "
                         "code in the sandbox; the targets must be unchanged)")
    rs.add_argument("--sandbox", default="stub", choices=["stub", "unshare"],
                    help="sandbox for --rerun-fix-gate")
    rs.add_argument("--assume-targets-unchanged", action="store_true",
                    help="allow --rerun-fix-gate on a run that recorded no target hashes")
    rs.set_defaults(func=cmd_rescore)

    st = sub.add_parser("status", help="show a run's state")
    st.add_argument("run_id")
    st.set_defaults(func=cmd_status)

    fn = sub.add_parser("findings", help="print a run's findings as JSON")
    fn.add_argument("run_id")
    fn.add_argument("--verdict", choices=["confirmed", "needs_validation", "rejected"],
                    default=None)
    fn.set_defaults(func=cmd_findings)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
