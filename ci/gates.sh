#!/usr/bin/env bash
# The AGENTS.md gates that are not cargo tests.
#
# G2 (vocabulary lock) is `cargo test` and G1 is cargo-deny. This script owns
# G5, G6, and G9, which are properties of the source text rather than of the
# compiled program.
set -euo pipefail

fail=0
note() { printf '  %s\n' "$1"; }

# --- G5: banned identifiers ------------------------------------------------
# Each name marks a design guestpass does not have. An inline
# `// ALLOW-BANNED: <reason>` on the same line suppresses one occurrence;
# writing the reason is the point of the escape hatch.
banned='cookie|session|jwt|sqlite|redirect|nonce|expires_in|refresh_token'

echo "G5: banned identifiers in src/"
while IFS= read -r line; do
  case "$line" in
    *ALLOW-BANNED:*) continue ;;
  esac
  note "$line"
  fail=1
done < <(grep -rniE "$banned" src/ --include='*.rs' || true)
[ "$fail" -eq 0 ] && note "clean"

# --- G9: no network listener exists ----------------------------------------
# Proving the absence is stronger than checking a bind address: if the program
# cannot name a TCP listener, no configuration can expose one.
echo "G9: no TCP listener in src/"
listener_dirty=0
while IFS= read -r line; do
  note "$line"
  listener_dirty=1
  fail=1
done < <(grep -rnE 'TcpListener|SocketAddr|0\.0\.0\.0' src/ --include='*.rs' || true)
[ "$listener_dirty" -eq 0 ] && note "clean"

# --- G6: the pure core stays pure ------------------------------------------
# policy/ and gate/ take time as an argument and perform no I/O, so their
# behaviour is reproducible from their inputs alone.
impure='Instant::now|SystemTime::now|OffsetDateTime::now|std::fs|tokio|reqwest'

echo "G6: no clock or I/O in policy/ and gate/"
core_dirty=0
while IFS= read -r line; do
  note "$line"
  core_dirty=1
  fail=1
done < <(grep -rnE "$impure" src/policy src/gate --include='*.rs' || true)
[ "$core_dirty" -eq 0 ] && note "clean"

exit "$fail"
