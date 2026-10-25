# OpenPlow — notes for Claude Code

OpenPlow is a vulnerability-discovery harness: Recon → Hunt → Validate → Gapfill →
Dedup → Report, driven by a SQLite task queue, with a finder model and a
*different* validator model. Start with `README.md`, then `docs/HANDOFF.md` for
the current state and next steps.

## Commands

```bash
pip install -e '.[dev]'            # dev install (pytest, pinned ruff, jsonschema)
ruff check openplow tests          # lint — must be clean
python -m pytest -q                # tests — no API key needed, ~10 s
```

CI runs exactly these on Python 3.11 and 3.13 for every PR and push to `main`.
Run both locally before pushing.

Free, offline checks of pipeline changes:

```bash
openplow benchmark benchmarks/cve/benchmark.json --adapter fixture:benchmarks/cve/fixture.json --out /tmp/ob-cve
openplow benchmark benchmarks/decoys/benchmark.json --adapter fixture:benchmarks/decoys/fixture.json --out /tmp/ob-decoys
openplow rescore <saved-benchmark-dir> --spec benchmarks/cve/benchmark.json
```

## Real-model runs cost money — always ask first

- Never start a real-model run (`scripts/run_real.sh`, `--adapter anthropic:...`)
  without the user's go-ahead and a spending cap: `OPENPLOW_MAX_COST=<USD>`.
  Ask what credit is left; keep the cap below it.
- The key is stored as `OPENPLOW_ANTHROPIC_API_KEY`, not `ANTHROPIC_API_KEY`,
  because Claude Code would use an `ANTHROPIC_API_KEY` in its own environment
  for its own requests. Map it for the one command only, and never print it:
  `ANTHROPIC_API_KEY="$OPENPLOW_ANTHROPIC_API_KEY" OPENPLOW_MAX_COST=2.00 scripts/run_real.sh ...`
- On macOS, set `OPENPLOW_SANDBOX=stub`: the default `unshare` sandbox is Linux-only.
- A smoke test of a change can use a Haiku finder, which is about 40× cheaper:
  `scripts/run_real.sh --benchmark <spec> claude-haiku-5-5 claude-sonnet-5-5`.

## Conventions

- Match the surrounding code: dataclasses, small module-level helpers,
  docstrings that say *why*, line length 100.
- Every behavior change gets a test. Model calls in tests use fake clients or
  adapters, never the network (see `tests/test_finder_tools.py`,
  `tests/test_cost_controls.py`).
- Work on a branch, and open a PR against `main`. Merge only when CI is green,
  and only when the user asks. Use merge commits.
- Benchmark targets (`benchmarks/cve/targets`, `benchmarks/decoys/targets`) must
  not reveal the answer. That means no `VULN`/`safe` comments, no docstrings
  naming the bug, and neutral directory names, because the finder reads the
  source and sees the directory name as the repo name. Decoys must be genuinely
  bug-free, including side issues such as size limits, resource cleanup and
  password storage.
- Results from runs made before PR #5 used targets that still had hints, so
  they overstate recall. Don't compare them directly with newer runs.

## Safety

OpenPlow writes and runs working exploit PoCs. Run it only against code the
user owns or is authorized to test. Use `--sandbox unshare` (Linux) for any
code that isn't one of the repo's own benchmark targets.
