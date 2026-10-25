#!/usr/bin/env bash
# Run lint and the full test suite inside a Linux container, so the `unshare`
# sandbox is exercised by a real kernel (macOS cannot run it).
#
# Usage:
#   scripts/test_linux.sh                    # ruff + the whole suite
#   scripts/test_linux.sh tests/test_x.py    # extra args go to pytest
#
# The container is --privileged and has a private cgroup namespace for TESTING
# ONLY: `unshare --mount-proc` fails in an unprivileged container. This is never
# the way to run OpenPlow; on a real Linux box it runs unprivileged.
#
# The container also delegates the memory controller (see the cgroup block below),
# playing the part systemd plays on a real machine, so the cgroup memory cap runs.
#
# The repo is mounted read-only and copied to /work first, so pytest and
# `pip install -e` never write into the host checkout.
set -euo pipefail

IMAGE="${OPENPLOW_TEST_IMAGE:-python:3.13-slim}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! docker info >/dev/null 2>&1; then
  echo "error: Docker is not reachable. Start Docker Desktop (or the docker daemon) and re-run." >&2
  exit 2
fi

echo "note: running in a --privileged container for TESTING ONLY (needed for unshare --mount-proc)." >&2

exec docker run --rm --privileged --cgroupns=private \
  -v "$ROOT":/src:ro \
  -e PYTHONDONTWRITEBYTECODE=1 -e DEBIAN_FRONTEND=noninteractive \
  -e PIP_ROOT_USER_ACTION=ignore \
  "$IMAGE" bash -euo pipefail -c '
    # Delegate the memory controller: a cgroup that holds processes cannot enable
    # controllers for its children, so move everything into "init" first, then
    # enable +memory on the (now empty) container root. OpenPlow only ever uses
    # what is already delegated; this is the harness doing it, not OpenPlow.
    cg=/sys/fs/cgroup
    if [ -w $cg/cgroup.subtree_control ]; then
      mkdir -p $cg/init
      for p in $(cat $cg/cgroup.procs); do echo $p > $cg/init/cgroup.procs 2>/dev/null || true; done
      echo +memory > $cg/cgroup.subtree_control || echo "note: memory controller not delegated" >&2
      echo $$ > $cg/init/cgroup.procs
    fi
    if ! command -v git >/dev/null; then
      apt-get update -qq && apt-get install -y -qq --no-install-recommends git >/dev/null
    fi
    mkdir /work
    tar -C /src --exclude=.git --exclude=.venv --exclude=__pycache__ -cf - . | tar -C /work -xf -
    cd /work
    pip install -q -e ".[dev]"
    ruff check openplow tests
    python -m pytest -q "$@"
  ' bash "$@"
