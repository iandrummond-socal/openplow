# Benchmarks

A benchmark is a set of target repos, each with a manifest of *known*
vulnerabilities, plus a spec that points at them. The harness runs the full
OpenPlow pipeline over every target and scores the findings against the
manifests.

## Run the sample

Deterministic, no API key — the `fixture` adapter replays canned findings so you
can see the scoring end to end:

```bash
openplow benchmark benchmarks/sample/benchmark.json \
  --adapter fixture:benchmarks/sample/fixture.json \
  --out openplow-benchmarks
```

Output lands in `openplow-benchmarks/`: `benchmark-report.md` (human) and
`benchmark-results.json` (machine).

## Run against a real model

```bash
export ANTHROPIC_API_KEY=...
openplow benchmark benchmarks/sample/benchmark.json \
  --adapter anthropic:<finder-id> \
  --validator-adapter anthropic:<validator-id> \
  --sandbox unshare
```

## Writing a benchmark

`benchmark.json`:

```json
{
  "name": "my-benchmark",
  "targets": [
    {"name": "svc", "path": "targets/svc",
     "expected": [
       {"id": "cve-1", "file": "src/x.py", "attack_class": "web-protocol-and-auth",
        "symbol": "handler", "line_range": [10, 40]}
     ]}
  ]
}
```

Paths are relative to the spec file. A finding matches a known vuln when they
share the **file** and **attack class**, and — when given — the **symbol**
appears in the finding and the **line** falls in `line_range`.

Good sources of known-vuln targets: CVE-fix commits (check out the parent of the
fix), deliberately vulnerable apps, and OSS-Fuzz reproducers.

## Metrics

| Metric | Meaning |
| --- | --- |
| recall | known vulns matched by any non-rejected finding / known vulns |
| confirmed recall | known vulns matched by a **confirmed** finding / known vulns |
| rejection rate | rejected findings / all candidate findings |
| unmatched confirmed | confirmed findings matching no known vuln (false positive *or* a new bug) |

Recall is not recall against *all* bugs — no such labeled set exists. It
measures only the bugs the manifest knows about. Use the rejection rate and the
coverage signal (Gapfill, later) to reason about completeness.
