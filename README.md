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
Recon  →  Hunt  →  Validate  →  Report
 map      break     adversarial   findings
 +        the       + PoC         + SARIF
 threat   code
 model
```

Each finding must carry a threat model, a proof-of-concept test that runs
against the **untouched** code, and a proposed patch. The validator is a fresh
agent that tries to disprove the finding and can never file one itself.

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

Run against a real model (finder and validator should differ so each checks the
other):

```bash
export ANTHROPIC_API_KEY=...
pip install -e '.[anthropic,schema]'
openplow run /path/to/target-repo \
  --adapter anthropic:<finder-model-id> \
  --validator-adapter anthropic:<validator-model-id> \
  --sandbox unshare
```

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

## Layout

| Path | What it is |
| --- | --- |
| `openplow/orchestrator.py` | Splits a run into tasks; drives stages; retries and resumes |
| `openplow/db.py` | SQLite state store keyed by `(run_id, repo, stage)` |
| `openplow/models.py` | Model-adapter interface + stub adapter |
| `openplow/sandbox.py` | OS-enforced sandbox for running target code (stub + unshare) |
| `openplow/stages/` | `recon`, `hunt`, `validate`, `report` |
| `openplow/schemas/` | Finding JSON schema |
| `skills/` | Vendored Cloudflare `security-audit` skill (see `skills/README.md`) |

## License

MIT. OpenPlow is derived in part from Cloudflare's `security-audit-skill`
(also MIT); see [`NOTICE`](NOTICE).

## Responsible use

OpenPlow finds exploitable bugs and writes working proofs of concept. Run it
only against code you own or are authorized to test, and handle findings under
a responsible-disclosure process.
