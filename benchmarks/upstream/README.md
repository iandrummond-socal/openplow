# Upstream CVE benchmark

Real project source at the commit *before* a security fix, used to measure
recall on code of real size and shape rather than on the minimal reproductions
in [`../cve/`](../cve/README.md). Each target ships a working PoC and a fix, and
is scored the same way: the finder must locate the defect, the PoC must
reproduce it on untouched code, and the fix must pass the fail→pass patch gate.

| Target (directory) | From | Advisory | Defect |
| --- | --- | --- | --- |
| `cpython-zip-ancestry-dos` (`archive-tree`) | zipp | python/cpython#123270 · CVE-2024-8088 | a zip entry name with repeated leading separators makes path enumeration loop forever (denial of service) |
| `pyjwt-hmac-key-confusion` (`token-verify`) | PyJWT | GHSA-ffqj-6fqr-9h24 · CVE-2022-29217 | an asymmetric public key is accepted as an HMAC secret, so anyone holding the public key can forge HS256 tokens |

## No hints — same rule as the CVE suite

The finder reads the source and the directory name, so a target that named its
project would let the finder recall the advisory instead of finding the bug. So
each target is the upstream source with **the package and identifying strings
renamed** (`zipp` → `ziptree`, `jwt`/PyJWT → `tokenlib`) and project URLs
removed. The code logic is unchanged — the vulnerable lines are the upstream
lines. Provenance, the real commits, and the licenses are recorded in the
repo's [`NOTICE`](../../NOTICE), which lives outside the target directories so
the finder never reads it.

Both projects are MIT licensed.

## A denial-of-service PoC must detect its own hang

The `archive-tree` bug is an infinite loop, not a crash, so the PoC cannot just
run the call and check the exit code — it would hang until the sandbox kills it,
which scores as "did not reproduce". Instead the PoC runs the vulnerable call in
a daemon thread, waits a few seconds, and if the thread is still alive treats
that as the hang: it prints its marker and exits 0. The marker is flushed before
`os._exit`, because `os._exit` does not flush stdout and the sandbox captures it
through a pipe.

## Run it

Deterministic, no API key (the `fixture` adapter replays the findings; the PoCs
and patch gate still run for real):

```bash
openplow benchmark benchmarks/upstream/benchmark.json \
  --adapter fixture:benchmarks/upstream/fixture.json
```

Expected: 100% recall and confirmed recall, both findings fix-verified.

Against a real model, each target is scanned fresh. These are real third-party
packages, so run them in the hardened sandbox:

```bash
openplow benchmark benchmarks/upstream/benchmark.json \
  --adapter anthropic:<finder-id> \
  --validator-adapter anthropic:<validator-id> \
  --sandbox unshare
```

## Decoys and the combined run

Each target has a bug-free twin: the same source with the real fix applied,
under `targets/archive-tree-safe` and `targets/token-verify-safe`. They are
marked `"decoy": true`, so anything the pipeline *confirms* on them is a false
positive by construction. `with-decoys.json` runs the two vulnerable targets and
their two decoys together, so one report shows recall and false positives side by
side:

```bash
openplow benchmark benchmarks/upstream/with-decoys.json \
  --adapter fixture:benchmarks/upstream/fixture.json
```

Expected: `recall=100%` and `decoys_clean=2/2 false_positives=0`. The fixture
replays the same exploit findings against every target; on a decoy the exploit
PoC runs against the fixed code and fails, so the finding is rejected. The decoys
are the maintainers' post-fix source, so they are free of the benchmarked bug;
as with any decoy, a genuine side bug found in one would score as a false
positive.

## Adding another upstream target

1. Find a fix commit in a small, dependency-light project. Check out its parent.
2. Copy only the source needed to run the bug into `targets/<neutral-name>/`,
   under a neutral package name. Remove the project name, URLs, and version
   metadata; leave the logic alone.
3. Record the project, the real commits, the advisory, and the MIT (or other)
   license in the repo `NOTICE` — not inside the target directory.
4. Write a PoC that reproduces on the untouched code and a patch that makes it
   stop. For a denial-of-service bug, detect the hang as above.
5. Add the target and its known-bug entry to `benchmark.json`, and the finding
   to `fixture.json` keyed by `<area>/<attack-class>` (the area is the target's
   top-level source directory). Run the fixture benchmark to check it scores.
