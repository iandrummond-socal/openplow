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
#
# Two modes:
#   default (OPENPLOW_TEST_USER unset)   the tests run as root inside the container.
#   OPENPLOW_TEST_USER=<numeric uid>     setup (cgroup delegation, pip install, ruff)
#                                        still runs as root; /work is chowned to that
#                                        uid and only the final pytest runs as it, via
#                                        `setpriv --reuid/--regid/--clear-groups`.
#                                        This proves the sandbox does not rely on the
#                                        caller being root. Tests that need to create a
#                                        cgroup leaf may skip in this mode.
#   e.g. OPENPLOW_TEST_USER=1000 scripts/test_linux.sh tests/test_sandbox_hardening.py
#
# The container is --privileged in BOTH modes: the privilege is what lets
# `unshare --mount-proc` work inside a container at all. Dropping to a uid
# inside it removes root from the test process, not from the container.
set -euo pipefail

IMAGE="${OPENPLOW_TEST_IMAGE:-python:3.13-slim}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_USER="${OPENPLOW_TEST_USER:-}"

if [ -n "$TEST_USER" ] && ! [[ "$TEST_USER" =~ ^[0-9]+$ ]]; then
  echo "error: OPENPLOW_TEST_USER must be a numeric uid (got '$TEST_USER')." >&2
  exit 2
fi

if ! docker info >/dev/null 2>&1; then
  echo "error: Docker is not reachable. Start Docker Desktop (or the docker daemon) and re-run." >&2
  exit 2
fi

echo "note: running in a --privileged container for TESTING ONLY (needed for unshare --mount-proc)." >&2

exec docker run --rm --privileged --cgroupns=private \
  -v "$ROOT":/src:ro \
  -e PYTHONDONTWRITEBYTECODE=1 -e DEBIAN_FRONTEND=noninteractive \
  -e PIP_ROOT_USER_ACTION=ignore -e OPENPLOW_TEST_USER="$TEST_USER" \
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
    if [ -n "$OPENPLOW_TEST_USER" ]; then
      # Hand /work (including the egg-info pip just wrote) to the test user, and
      # give it a HOME it owns; only pytest runs unprivileged.
      mkdir -p /work/.home
      chown -R "$OPENPLOW_TEST_USER:$OPENPLOW_TEST_USER" /work
      echo "note: tests run as uid $OPENPLOW_TEST_USER (non-root)" >&2
      HOME=/work/.home setpriv --reuid="$OPENPLOW_TEST_USER" --regid="$OPENPLOW_TEST_USER" \
        --clear-groups python -m pytest -q "$@"
    else
      echo "note: tests run as uid $(id -u) (root)" >&2
      python -m pytest -q "$@"
    fi
  ' bash "$@"
