"""OpenPlow command-line interface.

    openplow run <repo> [--adapter stub] [--validator-adapter ...] [--resume ID]
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
                     finder=finder, validator=validator, sandbox=sandbox)

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

    spec = load_spec(args.spec)
    out_dir = Path(args.out).resolve()
    print(f"OpenPlow benchmark '{spec.name}'  targets={len(spec.targets)}  "
          f"finder={args.adapter}  validator={args.validator_adapter or args.adapter}")
    report = run_benchmark(spec, finder_spec=args.adapter,
                           validator_spec=args.validator_adapter,
                           sandbox_kind=args.sandbox, out_dir=out_dir, effort=args.effort,
                           max_cost=args.max_cost)
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
    print(f"report: {out_dir / 'benchmark-report.md'}")
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
    bm.set_defaults(func=cmd_benchmark)

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
