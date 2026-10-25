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

The suite has 147 tests, all passing (24 of them run only on Linux), and lint is clean.

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
| no credits | Sandbox bug: as a non-root user `> /dev/null` fails (EACCES on `open(O_CREAT)` of a minimal-`/dev` node); root is fine. Caused by `minimal_dev` (passes with `minimal_dev=False`). `tests/test_sandbox_isolation.py::test_dev_null_can_be_redirected_to` is a strict xfail for non-root: when it is fixed the test XPASSes and fails the run until the marker is removed |
| no credits | Sandbox: `systemd-run --user` memory cap for desktop Linux, a non-privileged Linux CI job, loopback networking, runtime verification on x86_64 (roadmap M1) |

Sandbox state: done on Linux are the read-only target, capability drop, seccomp,
the delegated-cgroup cap, a minimal `/dev`, read-only `/proc` kernel controls, and
`socket(AF_UNIX)` refused by default (`socketpair` still allowed), and a minimal
read-only root: the payload sees only the host's `/usr` (and the `/bin /lib*` links),
a synthesised `/etc`, an empty `/tmp`, `/dev`, `/proc`, scratch and the target, never
`$HOME`, `/root`, `/var` or `/run`. A runtime outside `/usr` (nvm, pyenv, `/opt`) needs
`expose=[...]` or `OPENPLOW_SANDBOX_EXPOSE`. `enforced` now
also reports `minimal_dev`, `proc_hardened`, `unix_sockets_blocked` and `minimal_root`.
The minimal root is verified on aarch64 under Docker only (x86_64 and split-usr hosts
are not runtime-verified), is Linux only, and still leaves `/usr` and `/proc/self/mountinfo`
readable by design. The unix
socket default breaks a PoC that runs its own unix-socket server; such a PoC needs
`allow_unix_sockets=True`. `scripts/test_linux.sh` can run the tests as a non-root
user with `OPENPLOW_TEST_USER=<uid>`. On macOS and Windows the `stub` backend
enforces none of this.
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
