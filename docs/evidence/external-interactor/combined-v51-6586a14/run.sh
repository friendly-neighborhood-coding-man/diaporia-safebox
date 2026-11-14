#!/usr/bin/env bash
set -u
W=/home/user/combined-verify; OUT=/home/user/combined-evidence; PKG=$W/integrations/external-interactor
: > $OUT/exit-codes.txt
run() { local n="$1"; shift; local d="$1"; shift; ( cd "$d" && echo "\$ (cd ${d#$W/} && $*)" && "$@" ) > "$OUT/$n.log" 2>&1; echo "$n exit=$?" | tee -a $OUT/exit-codes.txt; }
{ echo "date: $(date -u +%FT%TZ)"; echo "node: $(node --version)"; echo "worktree HEAD: $(git -C $W rev-parse HEAD)"; echo "parents: $(git -C $W log -1 --format=%P)"; echo "V5.1 candidate: 6586a14 (PR #10); interactor candidate: 8acda53 (PR #9)"; } > $OUT/environment.txt
run root-npm-ci $W npm ci
run root-npm-test $W npm test
run pkg-npm-ci $PKG npm ci
run pkg-typecheck $PKG npm run typecheck
run pkg-build $PKG npm run build
run pkg-test $PKG npm test
run pkg-demo $PKG npm run demo -- --evidence $OUT/demo-mock-e2e.json
run root-npm-test-with-pkg-built $W npm test
run v5-mutations $W node --disable-warning=ExperimentalWarning scripts/v5/mutations.mjs $OUT/v5-mutations.json
run git-status-after-mutations $W git status --short
