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
> positives on bug-free decoys. Remaining M1 work is hardening the `unshare`
> sandbox. See [`docs/ROADMAP.md`](docs/ROADMAP.md), and
> [`docs/HANDOFF.md`](docs/HANDOFF.md) for the current state and next steps.

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

See [`benchmarks/README.md`](benchmarks/README.md).

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
| `openplow/sandbox.py` | OS-enforced sandbox: cleaned env, net isolation, rlimit caps (stub + unshare) |
| `openplow/poc.py` | Runs a finding's PoC against a pristine copy; detects tampering; fail→pass patch gate |
| `openplow/stages/` | `recon`, `hunt`, `validate`, `gapfill`, `dedup`, `report` |
| `openplow/benchmark.py` | Runs the pipeline over known-vuln and decoy targets; scores recall, noise, false positives |
| `openplow/rescore.py` | Re-scores a saved benchmark run offline (`openplow rescore`) |
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
