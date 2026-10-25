#!/usr/bin/env bash
# Run OpenPlow against a real Anthropic model, with preflight checks.
#
# Usage:
#   scripts/run_real.sh <target-repo> [finder-model] [validator-model]
#   scripts/run_real.sh --benchmark <spec.json> [finder-model] [validator-model]
#
# Defaults: finder claude-opus-5-5, validator claude-sonnet-5-5 (finder and
# validator should differ so each checks the other). Set OPENPLOW_SANDBOX and
# OPENPLOW_EFFORT to override the sandbox (default unshare) and effort (high).
# Set OPENPLOW_MAX_COST (USD) to cap estimated spend; the run stops making model
# calls once it is reached.
set -euo pipefail

FINDER_DEFAULT="claude-opus-5-5"
VALIDATOR_DEFAULT="claude-sonnet-5-5"
SANDBOX="${OPENPLOW_SANDBOX:-unshare}"
EFFORT="${OPENPLOW_EFFORT:-high}"
COST_ARGS=()
if [[ -n "${OPENPLOW_MAX_COST:-}" ]]; then
  COST_ARGS=(--max-cost "$OPENPLOW_MAX_COST")
fi

# ---- preflight ----------------------------------------------------------
if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
  echo "error: ANTHROPIC_API_KEY is not set. Export it and re-run:" >&2
  echo "  export ANTHROPIC_API_KEY=sk-ant-..." >&2
  exit 2
fi

if ! python3 -c "import anthropic" 2>/dev/null; then
  echo "installing the anthropic + jsonschema extras..." >&2
  pip install -e '.[anthropic,schema]' >/dev/null
fi

if ! command -v openplow >/dev/null 2>&1; then
  echo "installing openplow (editable)..." >&2
  pip install -e . >/dev/null
fi

# ---- dispatch -----------------------------------------------------------
if [[ "${1:-}" == "--benchmark" ]]; then
  SPEC="${2:?benchmark spec path required}"
  FINDER="${3:-$FINDER_DEFAULT}"
  VALIDATOR="${4:-$VALIDATOR_DEFAULT}"
  echo "benchmark=$SPEC finder=$FINDER validator=$VALIDATOR sandbox=$SANDBOX effort=$EFFORT max_cost=${OPENPLOW_MAX_COST:-none}"
  exec openplow benchmark "$SPEC" \
    --adapter "anthropic:$FINDER" \
    --validator-adapter "anthropic:$VALIDATOR" \
    --sandbox "$SANDBOX" --effort "$EFFORT" ${COST_ARGS[@]+"${COST_ARGS[@]}"}
else
  REPO="${1:?target repo path required}"
  FINDER="${2:-$FINDER_DEFAULT}"
  VALIDATOR="${3:-$VALIDATOR_DEFAULT}"
  echo "repo=$REPO finder=$FINDER validator=$VALIDATOR sandbox=$SANDBOX effort=$EFFORT max_cost=${OPENPLOW_MAX_COST:-none}"
  exec openplow run "$REPO" \
    --adapter "anthropic:$FINDER" \
    --validator-adapter "anthropic:$VALIDATOR" \
    --sandbox "$SANDBOX" --effort "$EFFORT" ${COST_ARGS[@]+"${COST_ARGS[@]}"}
fi
