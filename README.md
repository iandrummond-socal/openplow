# OpenPlow

A model-agnostic vulnerability discovery harness, built on Cloudflare's
MIT-licensed [`security-audit`](https://github.com/cloudflare/security-audit-skill)
skill and the approach described in
[Build your own vulnerability harness](https://blog.cloudflare.com/build-your-own-vulnerability-harness).

The skill is a single-session audit. OpenPlow is the durable machinery around
it: an orchestrator that splits a run into narrow agent tasks, a SQLite state
store so a crash loses only the task in flight, a model-agnostic adapter so the
finder and validator can be different models that check each other, and a
sandbox for running target code.

> **Status: M1 done, M2 under way.** The pipeline runs end-to-end against real
> models. The finder and validator read the target through read-only file tools.
> Every model call's raw output is saved for diagnosis. Refused requests fall back
> to another model. Prompts are cached, and a spending cap stops a run before it
> overspends. The benchmark measures recall on CVE reproductions and false
> positives on bug-free decoys. The `unshare` sandbox (Linux only) is read-only
> outside scratch, gives the payload a minimal `/dev` and a read-only `/proc/sys`
> (and the other kernel controls), drops capabilities and filters syscalls; a
> cgroup memory cap applies where one is delegated. By default it also refuses to
> create unix sockets (`socket(AF_UNIX)`), so the payload cannot reach host
> daemons; `socketpair` still works. That default breaks a PoC that runs its own
> unix-socket server: pass `allow_unix_sockets=True` for one. With that opt-in on,
> host sockets under `/run`, `/tmp` and `/var/run` are reachable, because hiding
> those directories is not built yet. On macOS and Windows the `stub` backend
> enforces none of this (only a cleaned env, a timeout and rlimits). See
> [`docs/ROADMAP.md`](docs/ROADMAP.md), and [`docs/HANDOFF.md`](docs/HANDOFF.md) for the current state and next steps.

## Why a harness and not just the skill

A single audit run finds about half of what repeated runs find, skews toward
simpler bugs, and loses hours of work if the session crashes. Cloudflare's
three walls — context exhaustion, no persistence, and blindness to cross-repo
bugs — are what the harness exists to climb. OpenPlow follows their advice:
start with **Recon → Hunt → Validate** and add a stage only when its absence is
a real bottleneck.

## Pipeline

```
Recon  →  Hunt  →  Validate  →  Gapfill  →  Dedup  →  Report
 map      break     adversarial   re-queue    fold      findings
 +        the       + PoC         thin cells  by root   + SARIF
 threat   code                    (bounded)   cause
 model
```

Recon, hunt, and validate run through the task queue. Gapfill, dedup, and report
run as finalization after the queue drains, so the report always reflects the
full, validated set (late finds included).

Each finding must carry a threat model, a proof-of-concept test that runs
against the **untouched** code, and a proposed patch. The validator runs the PoC
in the sandbox against a pristine copy of the target — reproduction is the
confirmation gate, and a PoC that edits source to "work" is rejected as tampered
— then a fresh agent (a different model) tries to disprove the finding. The
validator can never file one itself.

For a confirmed finding that ships a patch, the **fail→pass patch gate** then
runs: the PoC must reproduce, the patch is applied to the copy, and the PoC must
stop reproducing. Only a clean flip marks the fix verified (`fix.gate_passed`).
Model-written diffs often carry miscounted hunk lengths, so a rejected patch is
retried once with its hunk headers recounted.

How the stages use models:

- **Reading the code.** The hunter and the validator get read-only `list_files`,
  `read_file` and `grep` tools over the target (`openplow/repo_tools.py`). Paths
  are confined to the repo root, and output is capped in size. The validator is
  told to check the finding against the code, not the finding's own quotes.
- **Finding shape.** `attack_class` is the hunt cell's class. The model's own
  label, usually a CWE, goes in `weakness`. Dedup folds findings that share the
  file, the symbol and the first CWE they name, so one bug reported from several
  class angles counts once.
- **Diagnosis.** Each hunter and validator call is saved to
  `<run>/transcripts/{hunt,validate}/*.json`: the prompt, the reply, every tool
  call, the stop reason, refusal details and the model that served it. The
  report's wishlist flags unparseable replies, truncation and refusals.
- **Refusals.** Anthropic requests send `fallbacks: "default"`, so a request the
  safety classifier declines is re-run on the recommended model for that
  category. `provenance.served_by` records which model answered.

## Install

```bash
pip install -e .
```

Python 3.11+.

## Quick start

Run the full pipeline against a target repo using the built-in stub adapter
(no API key, deterministic, good for exercising the plumbing):

```bash
openplow run /path/to/target-repo --adapter stub
```

### Real-model run

Finder and validator should be **different** models so each checks the other.
The one-command runner does the preflight (key present, extras installed) for
you:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
# target repo:
scripts/run_real.sh /path/to/target-repo
# or the CVE benchmark:
scripts/run_real.sh --benchmark benchmarks/cve/benchmark.json
```

Defaults: finder `claude-opus-5-5`, validator `claude-sonnet-5-5`, sandbox
`unshare`, effort `high`. Override by passing model ids
(`scripts/run_real.sh <repo> claude-opus-5-5 claude-haiku-5-5`) or via
`OPENPLOW_SANDBOX` / `OPENPLOW_EFFORT`. Set `OPENPLOW_MAX_COST=<USD>` to cap
spend (see below).

The equivalent explicit command:

```bash
pip install -e '.[anthropic,schema]'
openplow run /path/to/target-repo \
  --adapter anthropic:claude-opus-5-5 \
  --validator-adapter anthropic:claude-sonnet-5-5 \
  --sandbox unshare --effort high
```

**Cost.** Every model call's token usage is recorded, billed to the model that
served it (a fallback may differ). The run and the benchmark print an estimated
cost, and the report has a per-model cost table. Prices are in
`openplow/pricing.py`; update them when rates change.

- **Spending cap.** `--max-cost USD`, or `OPENPLOW_MAX_COST` for
  `scripts/run_real.sh`, sets one budget shared by the finder, the validator and
  every benchmark target. It is checked before each API call. A call is refused
  unless the cap still leaves room for that call's largest possible output.
  Refused calls are not retried. A benchmark skips the targets it has not started
  and reports the results as incomplete.
- **Prompt caching.** The tool definitions, the system prompt and the
  attack-class methodology form one cached prefix per class. The tool loop also
  reads the growing conversation from cache. On a live check, a second hunt of
  the same class read over 90% of its prompt from cache on every turn.

Start on a small target to calibrate before a large scan.

Results land in `./openplow-runs/<run-id>/` and in the run database. Resume an
interrupted run:

```bash
openplow run /path/to/target-repo --resume <run-id>
```

Inspect a run:

```bash
openplow status <run-id>
openplow findings <run-id>
```

## Benchmark

Measure OpenPlow against targets with known vulnerabilities — recall, confirmed
recall, and the validation rejection rate. The sample runs deterministically
with no API key via the `fixture` adapter:

```bash
openplow benchmark benchmarks/sample/benchmark.json \
  --adapter fixture:benchmarks/sample/fixture.json
```

Swap in `--adapter anthropic:<finder-id> --validator-adapter anthropic:<validator-id>`
to score a real model. The suites:

- **`cve/`**: four reproductions of real advisories, used for recall. The target
  source and directory names carry no hints about the bug.
- **`decoys/`**: four look-alikes of the CVE targets with no bug. Anything
  confirmed on a decoy is a false positive.
- **`cve-and-decoys.json`**: runs both suites in one report.

After changing the dedup or scoring rules, re-score a saved run for free. No
model is called and no PoC is run:

```bash
openplow rescore openplow-benchmarks --spec benchmarks/cve/benchmark.json
```

Add `--rerun-fix-gate` to run the fix gate again on each confirmed finding that
ships a patch. This runs code in the sandbox (`--sandbox unshare` for anything
but the repo's own targets), still calls no model, and only makes sense when the
targets are unchanged. A run records a hash of each target; the re-run refuses if
a target differs. For a run made before hashes were recorded, pass
`--assume-targets-unchanged` if you know the targets have not changed.

See [`benchmarks/README.md`](benchmarks/README.md).

## Feedback loop

The harness learns from its own failures, during a run and across runs, and can test on a held-out benchmark whether that learning helps.

**What is learned.** Every failure the pipeline already detects is recorded as a *lesson signal*: a count of one kind of failure for one attack class, kept in the run database.
The kinds are a closed set, each with one fixed template in `openplow/feedback.py`:

- from validation: a PoC that did not reproduce, edited existing source, timed out, or was an `input`/`trace` PoC that cannot be run; a finding the validator disproved; a finding missing a part; a patch that failed the fix gate;
- from the hunter: a reply that could not be parsed, a reply cut off at the output limit, or a finding dropped as malformed;
- from a training benchmark only, because they need ground truth: a known bug that was missed, and a finding confirmed on a decoy.

The reply-shape kinds (unparseable, truncated, incomplete finding) apply to hunts of every class; the rest apply only to their own class.

**Where it shows.** A hunt prompt is built when its task is claimed, not when it is queued, so every hunt still waiting picks up the lessons learned so far.
The lessons go at the end of the user prompt as a `# Lessons from earlier tasks` section, at most six, most frequent first.
They never go in the system prompt, which is the cached prefix: lessons change during a run, and putting them there would break the cache for every hunt.
With no lessons the prompt is byte-identical to one built without the feedback loop.
Each hunt transcript lists the lessons its prompt held (`lessons`), and REPORT.md has a `Feedback (lesson signals)` table.

**Validations are claimed before hunts.** Recon queues every hunt before any validation exists, so with plain first-in-first-out order all first-round hunts would finish before the first failure was recorded.
The queue now claims `validate` tasks first, so each hunt's findings are judged, and their failures recorded, before the next hunt's prompt is built.

**Switches.** On `run` and `benchmark`:

- `--lessons FILE` imports a lessons file into the run (into every target's run for a benchmark). Counts are set, not added, so `--resume` with the same file does not double them.
- `--no-feedback` stops lessons learned in this run reaching later prompts. They are still recorded and reported, and imported lessons still apply.

On `benchmark` only, `--record-training-signals` records the two ground-truth kinds (written after each target finishes, so they never shape that target's own prompts) and `--export-lessons FILE` writes the lessons from every target's run to a file:

```bash
openplow benchmark benchmarks/cve-and-decoys.json \
  --adapter fixture:benchmarks/feedback/fixture.json \
  --record-training-signals --export-lessons lessons.json
openplow run /path/to/target-repo --lessons lessons.json
```

**The leakage rule.** A lessons file holds only `attack_class`, `kind` and `count`:

```json
{"version": 1,
 "lessons": [{"attack_class": "data-isolation-and-lifecycle", "kind": "poc_not_reproduced", "count": 3}]}
```

Any other field, an unknown class or kind, or a count below 1 is refused with a named reason.
There is nowhere to put a file name, a symbol or a finding title, so lessons learned on one benchmark cannot carry its answers into another's prompts.

**The held-out test.** A prompt change counts only if it moves results on code it was not tuned on.
`openplow feedback-eval` trains on one benchmark, exports the lessons, then runs a held-out benchmark twice and compares the arms:

```bash
openplow feedback-eval benchmarks/upstream/with-decoys.json \
  --train benchmarks/cve-and-decoys.json \
  --adapter fixture:benchmarks/feedback/fixture.json --out /tmp/ob-feval
```

Two comparison modes (`--compare`):

- `imported` (default): baseline against the lessons learned on `--train`. Both arms use the same models, sandbox, effort and in-run feedback setting (off unless `--in-run-feedback`), so the only difference is the imported lessons.
- `in-run`: no training (`--train` is refused). Baseline with in-run feedback off against the same benchmark with it on, so the only difference is whether lessons learned during the run reach the hunts still queued.

The verdict compares the second arm with the baseline, averaged over `--repeats` (default 1):

- `incomplete`: the spending cap was reached or a target was skipped in any phase, so nothing else is claimed.
- `no change` when training learned no lessons (`imported` mode): both arms ran the same prompts, so any difference, better or worse, is noise. This is decided before any regression or win.
- `regressed`: confirmed recall fell, or more findings were confirmed on decoys. The command exits 1.
- `improved`: not regressed, and confirmed recall rose, or more coverage cells hold a confirmed finding, or the rejection rate fell while filing at least as many candidates.
- `no change`: anything else, with the reason stated. Filing fewer is never a win: a rejection rate that fell only because fewer candidates were filed is reported as `no change`.

The command refuses a held-out target that shares a name or its source with a training target, or whose directory lies inside a training target's (or the reverse), and a target directory that is missing or empty.
It refuses an `anthropic:` adapter without `--max-cost`; one cap covers every phase.
A training target the cap cut short records no ground-truth signals, because its misses are not real misses.
A malformed spec exits 2, never 1, so a script can trust exit 1 to mean `regressed`.
It writes `lessons.json`, `feedback-eval.md` and `feedback-eval.json`, and the report says plainly that one run per arm is one sample.
The default split and how to run it for real: [`benchmarks/feedback/README.md`](benchmarks/feedback/README.md).

**What it deliberately does not do.**

- A refusal is not a lesson: guidance aimed at getting past a safety classifier would be evasion, not sharpening, so refusals stay on the wishlist for a person to read.
- A hunt that found nothing is not a lesson: most cells are legitimately empty, and gapfill already re-hunts thin cells.
- No model writes prompt text yet. Lessons are fixed templates, so they are free, deterministic and cannot leak. A model-written rewriter is a later step, and `feedback-eval` is the gate it will have to pass.

## Development

```bash
pip install -e '.[dev]'
ruff check openplow tests
python -m pytest -q
```

CI (`.github/workflows/ci.yml`) runs ruff and the tests on Python 3.11 and 3.13
for every PR and every push to `main`. The suite needs no API key. ruff is
pinned in the `dev` extra.

## Layout

| Path | What it is |
| --- | --- |
| `openplow/orchestrator.py` | Splits a run into tasks; drives stages; retries and resumes |
| `openplow/db.py` | SQLite state store keyed by `(run_id, repo, stage)` |
| `openplow/models.py` | Model adapters (stub, fixture, Anthropic with tool loop, caching, fallback), metering |
| `openplow/repo_tools.py` | Read-only, root-confined `list_files` / `read_file` / `grep` for the models |
| `openplow/sandbox.py` | OS-enforced sandbox: cleaned env, net isolation, rlimit caps, and for `unshare` a minimal read-only root (system runtimes only; `$HOME` and the rest of the host are not visible), a read-only filesystem, a minimal `/dev`, hardened `/proc`, no capabilities and a seccomp denylist that also refuses unix sockets (opt-in: `allow_unix_sockets=True`) |
| `openplow/_sandbox_init.py` | Runs inside the `unshare` namespaces: minimal root, minimal `/dev`, `/proc` hardening, read-only remount, capability drop, seccomp filter, then `exec` |
| `openplow/poc.py` | Runs a finding's PoC against a pristine copy; detects tampering; fail→pass patch gate |
| `openplow/stages/` | `recon`, `hunt`, `validate`, `gapfill`, `dedup`, `report` |
| `openplow/benchmark.py` | Runs the pipeline over known-vuln and decoy targets; scores recall, noise, false positives |
| `openplow/rescore.py` | Re-scores a saved benchmark run offline (`openplow rescore`) |
| `openplow/feedback.py` | Feedback loop: the closed set of lesson kinds and their templates; records, renders, exports and imports lessons |
| `openplow/feedback_eval.py` | Held-out test of the feedback loop (`openplow feedback-eval`): train, export, baseline vs lessons, verdict |
| `openplow/pricing.py` | Model prices, per-run cost estimation, spending cap (`Budget`) |
| `scripts/run_real.sh` | One-command real-model run, with preflight |
| `openplow/schemas/` | Finding JSON schema |
| `skills/` | Vendored Cloudflare `security-audit` skill (see `skills/README.md`) |
| `benchmarks/` | Benchmark specs: sample, CVE reproductions, decoys (see `benchmarks/README.md`) |
| `.github/workflows/ci.yml` | CI: ruff + pytest on Python 3.11 and 3.13 |
| `docs/` | Roadmap, cloud-run notes, handoff (current state and next steps) |
| `CLAUDE.md` | Project instructions for Claude Code sessions |

## License

MIT. OpenPlow is derived in part from Cloudflare's `security-audit-skill`
(also MIT); see [`NOTICE`](NOTICE).

## Responsible use

OpenPlow finds exploitable bugs and writes working proofs of concept. Run it
only against code you own or are authorized to test, and handle findings under
a responsible-disclosure process.
