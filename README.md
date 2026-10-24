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

> **Status: M1.** The pipeline runs end-to-end. Hunters build real prompts from
> the vendored Cloudflare skill class files and the recon context; model output
> is parsed and schema-checked before storage; the validator confirms or rejects
> on an explicit verdict. Point it at a real model with `--adapter anthropic:<model-id>`,
> or use the stub (no API key) to exercise the plumbing. Remaining M1 work is
> hardening the `unshare` sandbox. See [`docs/ROADMAP.md`](docs/ROADMAP.md).

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
`OPENPLOW_SANDBOX` / `OPENPLOW_EFFORT`.

The equivalent explicit command:

```bash
pip install -e '.[anthropic,schema]'
openplow run /path/to/target-repo \
  --adapter anthropic:claude-opus-5-5 \
  --validator-adapter anthropic:claude-sonnet-5-5 \
  --sandbox unshare --effort high
```

**Cost.** Every model call's token usage is recorded; the run and the benchmark
print an estimated cost and the report has a per-model cost table. Prices are in
`openplow/pricing.py` (update when rates change). Start on a small target to
calibrate before a large scan.

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
to score a real model. See [`benchmarks/README.md`](benchmarks/README.md).

## Layout

| Path | What it is |
| --- | --- |
| `openplow/orchestrator.py` | Splits a run into tasks; drives stages; retries and resumes |
| `openplow/db.py` | SQLite state store keyed by `(run_id, repo, stage)` |
| `openplow/models.py` | Model-adapter interface + stub adapter |
| `openplow/sandbox.py` | OS-enforced sandbox: cleaned env, net isolation, rlimit caps (stub + unshare) |
| `openplow/poc.py` | Runs a finding's PoC against a pristine copy; detects tampering; fail→pass patch gate |
| `openplow/stages/` | `recon`, `hunt`, `validate`, `gapfill`, `dedup`, `report` |
| `openplow/benchmark.py` | Runs the pipeline over known-vuln targets and scores recall + noise |
| `openplow/pricing.py` | Model prices + per-run cost estimation |
| `scripts/run_real.sh` | One-command real-model run, with preflight |
| `openplow/schemas/` | Finding JSON schema |
| `skills/` | Vendored Cloudflare `security-audit` skill (see `skills/README.md`) |
| `benchmarks/` | Benchmark specs + sample known-vuln targets (see `benchmarks/README.md`) |

## License

MIT. OpenPlow is derived in part from Cloudflare's `security-audit-skill`
(also MIT); see [`NOTICE`](NOTICE).

## Responsible use

OpenPlow finds exploitable bugs and writes working proofs of concept. Run it
only against code you own or are authorized to test, and handle findings under
a responsible-disclosure process.
