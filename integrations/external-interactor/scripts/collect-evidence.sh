#!/usr/bin/env bash
# Reruns the integration package checks and the SafeBox root regression suite; records commands, outputs and exit codes.
set -u
PKG="$(cd "$(dirname "$0")/.." && pwd)"; ROOT="$(cd "$PKG/../.." && pwd)"
OUT="${1:-$ROOT/docs/evidence/external-interactor}"; mkdir -p "$OUT"
run() { local name="$1"; shift; local dir="$1"; shift; ( cd "$dir" && echo "\$ (cd ${dir#$ROOT/} && $*)" && "$@" ) > "$OUT/$name.log" 2>&1; local rc=$?; echo "$name exit=$rc" | tee -a "$OUT/exit-codes.txt"; }
: > "$OUT/exit-codes.txt"
{ echo "date: $(date -u +%FT%TZ)"; echo "node: $(node --version)"; echo "npm: $(npm --version)"; echo "head: $(git -C "$ROOT" rev-parse HEAD)"; echo "os: $(uname -sr)"; } > "$OUT/environment.txt"
run pkg-npm-ci "$PKG" npm ci
run pkg-typecheck "$PKG" npm run typecheck
run pkg-build "$PKG" npm run build
run pkg-test "$PKG" npm test
run pkg-demo "$PKG" npm run demo -- --evidence "$OUT/demo-mock-e2e.json"
run root-npm-test "$ROOT" npm test
cat "$OUT/exit-codes.txt"
