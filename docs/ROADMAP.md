# OpenPlow roadmap

Milestones follow the build plan. Estimates assume one engineer working with a
coding agent.

## M0 — Spike (done conceptually; baseline still to run)
Run the Cloudflare skill unchanged on 3–5 repos with known CVEs to set a
recall/precision baseline before building machinery.

## M1 — MVP (this scaffold)
Components 1–8, one repo, CLI only.

- [x] Orchestrator + SQLite task queue (`orchestrator.py`, `db.py`)
- [x] Model-adapter layer with explicit ok/retryable/fatal classification (`models.py`)
- [x] Recon → coverage ledger → enqueue hunts (`stages/recon.py`)
- [x] Hunt task shape + streaming findings (`stages/hunt.py`)
- [x] Validator: deterministic Pass 1 + adversarial Pass 2 hook (`stages/validate.py`)
- [x] Reporter: REPORT.md + findings.json + SARIF (`stages/report.py`)
- [x] Sandbox interface: stub + unshare backend (`sandbox.py`)
- [x] Finding JSON schema (`schemas/finding.schema.json`)
- [x] Wire a real finder model and a *different* validator model (`models.AnthropicAdapter`, separate `--validator-adapter`)
- [x] Parse real model findings and validate them against the schema (`findings.py`)
- [x] Vendor the Cloudflare skill class files into `skills/` and drive hunter prompts from them (`skill_loader.py`)
- [x] Validator confirms/rejects on an explicit `VERDICT:` line; severity only on confirmed
- [x] Harden the sandbox: cleaned env, net isolation (`unshare --net`), rlimit caps — cpu, file size, procs, optional address space (`sandbox.py`)
- [x] Run PoCs against a pristine copy with source-integrity (tamper) detection (`poc.py`); reproduction is the confirmation gate
- [ ] Sandbox: seccomp profile, read-only bind of the target, cgroup-v2 memory cap
- [x] Fail→pass patch gate: reproduce → apply the finding's patch → must not reproduce; only a clean flip passes (`poc.run_patch_gate`, wired into validate; `fix.gate_passed` on confirmed findings, counted in the report)

## M2 — Coverage
Components 9–13 plus an evaluation suite.

- [x] Gapfill: re-queue thin `(area x class)` cells (deeper passes), bounded rounds (`stages/gapfill.py`)
- [x] Dedup: root-cause key from inverted indexes (file, symbol, class, boundary); stable cross-run key; marks canonical vs duplicate (`stages/dedup.py`)
- [x] Finalization ordering: gapfill → dedup → report run after the queue drains, so the report sees the full validated set
- [x] Wishlist surfaced as a report section (store table + report wired)
- [x] Benchmark harness over known-vuln repos; recall + rejection rate (`benchmark.py`, `benchmarks/`)
- [x] `fixture` adapter for deterministic, no-API-key benchmark/scoring runs
- [x] Fix: task identity scoped to `(run_id, task_id)` so several runs share one DB (surfaced by the benchmark)
- [x] Fix: a re-hunt no longer resets an already-stored finding (first report of an id wins)
- [x] CVE benchmark suite: 4 real-advisory reproductions (CVE-2007-4559, Zip Slip, SQLi, cmd injection) with working PoCs + real fixes; all confirm and pass the patch gate (`benchmarks/cve/`)
- [x] PoC integrity model: only edits to *pre-existing* source count as tampering (new files an exploit creates are fine); patch gate uses separate fresh copies for before/after
- [x] Real-model run wired up: `AnthropicAdapter` with effort + usage capture, `MeteredAdapter`, `pricing.py` cost estimation, `scripts/run_real.sh` one-command runner with preflight; run and benchmark print estimated cost
- [ ] Feedback loop: rewrite queued prompts from failures, tested on a held-out repo
- [ ] More gapfill rounds driven by a coverage metric rather than a fixed cap
- [ ] Add upstream CVE-fix targets (check out the pre-fix commit) alongside the reproductions
- [x] Prompt caching: class file moved into the cached system prefix, plus automatic caching of the tool-loop conversation (`models.AnthropicAdapter`)
- [x] Spending cap: `--max-cost` / `OPENPLOW_MAX_COST`, one budget shared by finder, validator and all benchmark targets; checked before every API call (`pricing.Budget`)

## M3 — Fleet
Components 14–17.

- [ ] Cross-repo symbol index + dependency graph; spawn hunts in consumer repos
- [ ] Judgment agent: production reachability, owner, severity, recheck on main
- [ ] Fixer: patch + fail→pass regression gate; opens a PR, never merges
- [ ] Ops: worker pool against one store, per-repo budgets/caps, scheduled sweeps

## Known design constraints
- Finder and validator must be different models.
- No finding ships without a PoC that runs on untouched code.
- The fixer never merges; severity and disclosure stay with people.
- Run it only against code you own or are authorized to test.
