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
