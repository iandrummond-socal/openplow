# CVE benchmark

Small, self-contained targets that reproduce well-known vulnerability classes,
each mapped to a real advisory and shipped with a working PoC and the real fix.

These are **minimal reproductions**, not upstream code copied verbatim: each
target is a few lines that exhibit the same defect as the cited advisory, so the
benchmark stays self-contained, dependency-free (standard library only), and
runnable offline in the sandbox. The point is to check whether OpenPlow finds
the defect, confirms it by running a PoC against the untouched code, and
verifies the shipped fix with the fail→pass patch gate.

| Target | Advisory | Defect | Fix |
| --- | --- | --- | --- |
| `cve-2007-4559-tarfile` | CVE-2007-4559 | `tarfile.extractall` trusts member names → directory traversal | validate each member resolves inside dest |
| `zip-slip` | Zip Slip (Snyk, 2018) · CWE-22 | manual zip extraction joins entry name without checking → traversal | check the resolved path stays under dest |
| `sqli-sqlite` | CWE-89 (representative of many CVEs) | user input string-formatted into SQL → auth bypass | parameterized query |
| `cmd-injection` | CWE-78 (representative of many CVEs) | host interpolated into a `shell=True` command → RCE | pass an argv list, no shell |

## Run it

Deterministic, no API key (the `fixture` adapter replays the findings + PoCs +
fixes so the scoring, PoC execution, and patch gate all run):

```bash
openplow benchmark benchmarks/cve/benchmark.json \
  --adapter fixture:benchmarks/cve/fixture.json
```

Expected: 100% recall and confirmed recall, and every finding "Fix verified
(fail→pass patch gate)". The rejection rate is non-zero because the fixture
replays every target's findings into every target run, so each run correctly
rejects the findings that cite files it does not contain — a useful check that
validation rejects findings whose cited code is absent.

Run against a real model (each target scanned fresh, no replay):

```bash
export ANTHROPIC_API_KEY=...
openplow benchmark benchmarks/cve/benchmark.json \
  --adapter anthropic:<finder-id> \
  --validator-adapter anthropic:<validator-id> \
  --sandbox unshare
```

## Adding real upstream CVE-fix targets

To benchmark against upstream code rather than a reproduction, check out the
commit *before* a CVE fix into a new `targets/<name>/` directory, add the known
vuln to the manifest (file, attack class, symbol, line range), and — if you want
the deterministic path — add a fixture finding with a PoC that reproduces in the
sandbox and the upstream fix as the patch. Keep targets small and offline.
