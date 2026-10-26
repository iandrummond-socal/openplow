# Feedback-loop held-out test

`openplow feedback-eval` checks whether lessons learned on one benchmark help on code they were never learned from.
This folder holds the fixture for the free run of the default split.
How the feedback loop works is in the main [`README.md`](../../README.md#feedback-loop).

## The default split

- **Train:** [`../cve-and-decoys.json`](../cve-and-decoys.json), the four CVE reproductions and their four bug-free decoys.
- **Held out:** [`../upstream/with-decoys.json`](../upstream/with-decoys.json), real project source at the commit before a security fix (zipp, PyJWT), renamed, with a bug-free twin of each.

Why this way round: the upstream targets are real code of real size, renamed so the finder cannot recall the advisory.
They are the closest thing in the repo to "a repo the prompts were not tuned on", so they are what a lesson has to move.
The reproductions are small and written for this project, which makes them the place to learn from.
The command refuses a held-out target that shares a name or its source with a training target.

Lessons are per attack class, and the reply-shape kinds apply to every class.
A class-specific lesson reaches a held-out hunt only when training recorded it for that hunt's class.

## Run it free

`fixture.json` merges the hunts of `../cve/fixture.json` and `../upstream/fixture.json`, so one fixture adapter serves both phases.
No model is called; the PoCs and patch gate still run in the sandbox:

```bash
openplow feedback-eval benchmarks/upstream/with-decoys.json --train benchmarks/cve-and-decoys.json --adapter fixture:benchmarks/feedback/fixture.json --out /tmp/ob-feval
```

It prints `verdict: no change`: the fixture replays the same findings whatever the prompt says, so lessons cannot move it.
That proves the plumbing (train, export, both arms, the report), not the lessons.
Output in `--out`: `lessons.json` (written before the held-out phase), `feedback-eval.md`, `feedback-eval.json`, and one benchmark directory per phase (`train/`, `holdout-baseline-1/`, `holdout-lessons-1/`).

## Run it for real

Real runs cost money.
Never start one without Big Dawg's go-ahead and a cap below the credit left.
`feedback-eval` refuses an `anthropic:` adapter without `--max-cost`, and that one cap covers every phase together.

Map the stored key for the one command only (see `CLAUDE.md`), and on macOS use the `stub` sandbox, because `unshare` is Linux-only.
A Haiku finder is the cheap first look:

```bash
ANTHROPIC_API_KEY="$OPENPLOW_ANTHROPIC_API_KEY" openplow feedback-eval \
  benchmarks/upstream/with-decoys.json --train benchmarks/cve-and-decoys.json \
  --adapter anthropic:claude-haiku-5-5 --validator-adapter anthropic:claude-sonnet-5-5 \
  --sandbox stub --max-cost <USD> --out openplow-feedback-eval
```

`scripts/run_real.sh` does not wrap `feedback-eval`, so `OPENPLOW_SANDBOX` and `OPENPLOW_MAX_COST` do nothing here: pass `--sandbox` and `--max-cost` on the command line.
A full run is one training benchmark plus two held-out benchmarks (more with `--repeats`).
If the cap is reached, the verdict is `incomplete` and nothing else is claimed.

## The two comparison modes

- `--compare imported` (default) proves that lessons learned elsewhere transfer.
  Baseline against the lessons exported from `--train`; both arms use the same models, sandbox, effort and in-run feedback setting (off unless `--in-run-feedback`).
- `--compare in-run` proves that the in-run loop helps on code it never saw: hunts still queued built with the lessons of earlier tasks, which needs validations claimed before hunts.
  No training, so `--train` is refused; the baseline runs with in-run feedback off and the other arm with it on.

```bash
openplow feedback-eval benchmarks/upstream/with-decoys.json --compare in-run --adapter fixture:benchmarks/feedback/fixture.json --out /tmp/ob-feval-inrun
```

Neither mode says anything about bugs the manifests do not know.

## Coverage cells

`cells_covered` counts the distinct `(area, attack_class)` cells, Cloudflare's coverage measure, that hold at least one confirmed, canonical finding on a non-decoy target.
Rejected, unvalidated, duplicate and decoy findings never raise it, so filing noise cannot pass for coverage.
A rise in coverage cells is one of the ways the verdict can be `improved`; the benchmark and `rescore` reports show it too.

## Honesty about the result

One run per arm is one sample.
Real models are noisy, and the held-out set has four targets, so a small difference is noise until `--repeats` confirms it; the report says so.
Arm order alternates per repeat to spread any drift, and the order run is recorded.

A held-out set used to tune repeatedly becomes training data.
Every time a result on `upstream/` steers a change, a little of it leaks into the prompts.
That matters most for a future model-written rewriter: before its results can be trusted it needs a fresh held-out target, or a rotating one.
