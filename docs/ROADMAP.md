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
- [ ] Fail→pass patch gate (run PoC, apply the finding's patch, confirm it no longer reproduces)

## M2 — Coverage
Components 9–13 plus an evaluation suite.

- [ ] Gapfill: re-queue thin `(area x class)` cells and zero-finding hunts
- [ ] Dedup: inverted indexes + root-cause clustering, stable cross-run keys
- [ ] Streaming producer/consumer across gapfill/validate/dedup/report
- [ ] Wishlist surfaced as a report section and a build-priority signal (store table exists)
- [ ] Feedback loop: rewrite queued prompts from failures, tested on a held-out repo
- [ ] Benchmark harness over known-CVE repos; track validation rejection rate

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
