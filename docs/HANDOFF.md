# Handoff — 2026-10-25

This file moves OpenPlow work from a Claude Code cloud session to a local one.
Claude Code loads `CLAUDE.md` (repo root) by itself; this file adds the current
state and next steps. Read both before starting.

## Current state

`main` has everything; there are no open PRs. Merged in this round:

| PR | What it did |
| --- | --- |
| #1 | Finder and validator read the target through read-only file tools; raw model output saved to `transcripts/`; refusal fallback; scoring by file + symbol/line; patch hunk recount |
| #2 | Dedup keyed on file + symbol + first CWE named |
| #3 | Prompt caching; spending cap (`--max-cost`, `OPENPLOW_MAX_COST`) |
| #4 | Decoy targets (no bug) to measure false positives |
| #5 | Hints removed from the CVE targets (comments, docstrings, directory names) |
| #6 | CI: ruff + pytest on Python 3.11 and 3.13 |
| #7 | `openplow rescore`: re-score a saved run offline |

The suite has 102 tests, all passing, and lint is clean.

## Results so far, and their limits

Five real runs were made, with finder `claude-opus-5-5` and validator
`claude-sonnet-5-5`. By the last runs, every known bug was found and confirmed,
and most patches passed the fix gate.

All five ran **before PR #5**, so the target source still named each bug. Their
recall figures are inflated. The saved run data was in the cloud container and
is not kept. No real run has been made yet on:

- the hint-free CVE targets (true recall);
- the decoys (false-positive rate);
- the cached prompts (cost after caching).

## Local setup

```bash
git clone https://github.com/iandrummond-socal/openplow.git
cd openplow
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[dev,anthropic]'
ruff check openplow tests && python -m pytest -q
```

API key for real runs: keep it out of the shell that starts Claude Code, or
Claude Code will bill its own requests to it. Store it as
`OPENPLOW_ANTHROPIC_API_KEY`, for example in your shell profile or a password
manager, and pass it to one command at a time:

```bash
ANTHROPIC_API_KEY="$OPENPLOW_ANTHROPIC_API_KEY" OPENPLOW_SANDBOX=stub OPENPLOW_MAX_COST=2.00 \
  scripts/run_real.sh --benchmark benchmarks/decoys/benchmark.json
```

On macOS keep `OPENPLOW_SANDBOX=stub`: the `unshare` sandbox needs Linux.

## Housekeeping on GitHub

- **Delete the merged branches.** These are still on GitHub: `finder-repo-tools`,
  `dedup-by-cwe`, `cost-controls`, `decoy-targets`, `neutral-cve-targets`, `ci`
  and `rescore`. The cloud session could not delete remote branches.
- **Auto-delete future branches.** Turn on Settings → General → "Automatically
  delete head branches".
- **Require CI.** Under Settings → Branches, make `lint`, `test (3.11)` and
  `test (3.13)` required checks for `main`.

## Next steps

| Needs | Task |
| --- | --- |
| no credits | Sandbox: `systemd-run --user` memory cap for desktop Linux, and an unprivileged-Linux CI job (roadmap M1; read-only target, capability drop, seccomp and the delegated-cgroup cap are done) |
| ~$2 credit | Decoys-only real run → first false-positive rate |
| ~$5–6 credit | `benchmarks/cve-and-decoys.json` real run → honest recall and false positives in one report |

API credit left at handoff: about $2.40 by estimate. Check the Anthropic
console for the real figure.

## First prompt for the local session

Paste this into Claude Code from the repo root:

> Read CLAUDE.md and docs/HANDOFF.md. Then run lint and the tests to confirm
> the checkout is healthy, and tell me the result. Don't start any real-model
> run without asking me first. After that, propose which item from "Next steps"
> to do first and why.
