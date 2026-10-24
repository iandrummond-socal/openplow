# Running OpenPlow in a Claude Code cloud session

OpenPlow calls the Anthropic API directly (via `ANTHROPIC_API_KEY`), so a cloud
session needs that key as an environment secret and network access to the API.
A cloud session only picks up these settings if they are saved **before** the
session starts.

## One-time environment setup

In the cloud environment's settings (the environment menu in a session's title
bar → **Edit**):

1. **Secret.** Add `ANTHROPIC_API_KEY` (your `sk-ant-...` key) under **Network
   secrets** / **API credentials**, or as an environment variable named exactly
   `ANTHROPIC_API_KEY`. Never paste the key into chat.
2. **Network.** Ensure the policy allows `api.anthropic.com`. On the **Limited**
   level, add `api.anthropic.com` under **Allowed domains** and keep **Allow
   package managers** ticked (so `pip` can install the extras). Broader levels
   already allow it.

## What the session runs

The session clones this repo and runs the CVE benchmark against real models:

```bash
export ANTHROPIC_API_KEY   # already set as an env secret
OPENPLOW_SANDBOX=stub scripts/run_real.sh --benchmark benchmarks/cve/benchmark.json
```

Defaults: finder `claude-opus-5-5`, validator `claude-sonnet-5-5`, effort
`high`. The script installs the `anthropic` + `schema` extras, runs the four CVE
targets, and prints recall, confirmed recall, rejection rate, and the
**estimated cost**; the full report is written to
`openplow-benchmarks/benchmark-report.md`.

The CVE targets are OpenPlow's own trusted reproductions, so the `stub` sandbox
(clean env + rlimits, runs the PoCs) is enough and avoids relying on `unshare`,
which a restricted container may block (it needs `seccomp=unconfined` and
`apparmor=unconfined` under Docker). For scanning **untrusted / third-party**
code, use `--sandbox unshare` so the network is isolated:

```bash
scripts/run_real.sh /path/to/target-repo   # defaults to unshare
```

## Expected signal

For each of the four CVE targets, a capable finder should produce a finding
whose PoC reproduces in the sandbox and whose patch passes the fail→pass gate.
The benchmark reports this as recall / confirmed recall; unmatched confirmed
findings are possible false positives or genuinely new bugs.
