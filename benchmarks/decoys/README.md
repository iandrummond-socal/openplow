# Decoy benchmark

Four targets shaped like the [CVE benchmark](../cve/README.md) targets, with the
same file names and function signatures, but **without the bug**. They measure
false positives: anything the pipeline *confirms* on a decoy is a false positive
by construction. Recall is not measured on decoys.

Each decoy also closes the adjacent issues real finders raised on the CVE
targets (decompression bombs, unclosed connections, plaintext passwords), so a
confirmed finding cannot be a genuine side bug. The code carries no "safe" or
"fixed" comments, and the directory names are neutral, because the repo name
and source are what the finder sees.

| Target (directory) | Looks like | Why it is not vulnerable |
| --- | --- | --- |
| `decoy-tar-extract` (`tar-extract`) | `cve-2007-4559-tarfile` | uncompressed tar only; every member must be a regular file or directory and resolve inside dest; caps on archive size, member count and total size; files are written by hand, so no links, devices or mode bits are ever created |
| `decoy-zip-extract` (`zip-extract`) | `zip-slip` | every entry must resolve inside dest before anything is written; caps on archive size, entry count and declared total size; copies are bounded by each entry's declared size |
| `decoy-sqlite-login` (`sqlite-login`) | `sqli-sqlite` | parameterized queries; salted scrypt hashes compared with `hmac.compare_digest`; a dummy hash for unknown users so timing does not reveal names; connections closed with `contextlib.closing` |
| `decoy-net-ping` (`net-ping`) | `cmd-injection` | host must be an IP address or a valid hostname; argv list with no shell; `--` ends options; timeout |

## Run it

Deterministic, no API key. The fixture files an exploit claim for each decoy,
and the fixture validator always answers "confirmed", so every rejection comes
from the exploit PoC actually failing against the decoy:

```bash
openplow benchmark benchmarks/decoys/benchmark.json \
  --adapter fixture:benchmarks/decoys/fixture.json
```

Expected: `decoys_clean=4/4 false_positives=0`. The fixture's exploit PoCs are
the real thing: the tests run the tar, zip and command-injection ones against
the matching CVE targets and check that they break them.

With a real model, run the decoys on their own, or together with the CVE targets
so one report shows recall and false positives side by side:

```bash
OPENPLOW_MAX_COST=2.00 scripts/run_real.sh --benchmark benchmarks/decoys/benchmark.json
OPENPLOW_MAX_COST=4.00 scripts/run_real.sh --benchmark benchmarks/cve-and-decoys.json
```

## Adding a decoy

Add a target with `"decoy": true` and no `expected` list. The loader refuses a
decoy that lists expected vulns. Make sure the code is genuinely free of bugs,
including side issues, or a correct finding will be scored as a false positive.
