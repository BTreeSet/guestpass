#!/usr/bin/env bash
# Everything CI runs, in CI's order, as one command.
#
# Its reason for existing: running a subset locally and reporting it as the
# whole set is the failure this script removes. `upstream-ci.yaml` calls the
# same steps; keep the two in step.
set -euo pipefail

export GUESTPASS_SKIP_FRONTEND_BUILD=1

step() { printf '\n=== %s ===\n' "$1"; }

step "cargo fmt"
cargo fmt --all --check

step "cargo clippy"
cargo clippy --all-targets --locked -- -D warnings

step "cargo test"
cargo test --locked

step "gates G5, G6"
./ci/gates.sh

step "cargo-deny (G1)"
if command -v cargo-deny >/dev/null 2>&1; then
  cargo deny check advisories bans licenses sources
else
  echo "  cargo-deny absent; CI runs it via the pinned action"
fi

step "frontend"
if command -v npm >/dev/null 2>&1; then
  (cd frontend && npm ci --silent && npm run build)
else
  echo "  npm absent; CI runs the frontend job"
fi

printf '\nall checks passed\n'
