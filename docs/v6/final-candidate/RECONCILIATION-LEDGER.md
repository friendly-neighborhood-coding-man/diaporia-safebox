# Patch ledger: PR #28 findings reconciled onto the PR #26 freeze

Base: `60cfd20` (PR #26 frozen V6 candidate, untouched). New candidate branch: `integration/v6-final-candidate`.
Scope rule (Eric 2026-11-14 17:47Z): only submission-critical security changes go into the V6 candidate; V1/V2
legacy hardening goes to a separate branch (`security-research/v1v2-legacy-hardening`) that is never applied to the
candidate automatically. No original PR (#19-#28) was merged, rebased or pushed to.

| PR | Topic | Decision | Where | Reason |
|---|---|---|---|---|
| #20 | Root dispatch: inherited `Object.prototype` names act as handlers | **ACCEPTED** (cherry-pick of `8778ce0`) + **direct V3/V4/V5/V6 regression added** | candidate | Reproduced on `60cfd20`: V3 and V4 commit `toString` / `constructor`; V5 and V6 commit 8 inherited names; a function planted on `Object.prototype` sets epoch to 99 in all four. Unauthenticated Root commit = HIGH. PR #28's condition (V3 revert not covered) fixed: `tests/v3/prototype-action.test.mjs` fails 4/4 on `60cfd20` and fails when the V3, V4 or V5 lookup alone is reverted. |
| #22 | Gmail credential files follow symlinks, ignore mode | **SUPERSEDED / MERGED BY HAND** into PR #26's loader (not cherry-picked) | candidate | #26 already had the stronger read path (O_NOFOLLOW + O_NONBLOCK FIFO guard + fstat). A cherry-pick would have dropped O_NONBLOCK. Kept #26; added #22's 0600 check, bounded read, `writeGmailCredentialFile`; moved field validation (control characters, length) into the writer per PR #28's condition. Windows: mode check skipped (ACL), O_NOFOLLOW absent: documented residual. |
| #25 | Showcase console line splits on newline | **SUPERSEDED** by PR #26 `termSafe` (not cherry-picked) | candidate | #25 only flattens CR/LF; `termSafe` also escapes U+2028/U+2029, ANSI CSI, C1 and bidi controls (PR #28's #25 residuals). #25's case and the residuals are tested in `tests/v6/showcase-log-reconcile.test.mjs`. The viewer now escapes kind/labels/time as well (defence in depth; those were constants). |
| #19 | V2 keygen check-then-create, symlink follow | **ACCEPTED** (cherry-pick `d33a682`) | Track C branch | Valid (PR #28 reproduced), but V2 legacy code, not in the V6 submission path. |
| #21 | V2 launcher paths interpolated into `sh -c` | **ACCEPTED WITH FIXES** (cherry-pick `8fdcd9a` + `3f0e5b3`) | Track C branch | PR #28 conditions fixed: absolute-path operands (GNU find parses a leading `-` even after `--`), `--` for stat, MASK mount paths quoted, find failures recorded as `FIND_FAILED`. Launcher executed for real here (container root): V2/V3 OS tests 6/6. |
| #23 | V1 owner/executor key files follow symlinks | **ACCEPTED** (cherry-pick `631fa42`) | Track C branch | V1 legacy. |
| #24 | V2 owner log view follows symlinks | **ACCEPTED WITH FIX** (cherry-pick `e62c3e5` + `a11b8b6`) | Track C branch | PR #28 condition fixed: the writer now appends through an O_NOFOLLOW descriptor (`OWNER_LOG_SYMLINK`). |
| #18 | SSTP verifySlot (older version) | **SUPERSEDED** by PR #27 | n/a | PR #28 reviewed #18; #27 is the later implementation and is evaluated separately (SSTP report). |
| #27 | SSTP verifySlot fd read + directory pinning | **NOT INTEGRATED** (SSTP is separate research) | `security-research/sstp-pr27-verification` (evaluation only) | PARTIAL FIX: directory swap-and-swap-back still succeeds (interposition and real timing race). See SSTP-PR27-EVALUATION.md. |
| #17 | Audit report | reference only | n/a | |
| #28 | Independent review | reference only | n/a | Every finding above traced to a decision. |

Additional candidate changes (not from a PR):

| Change | Reason |
|---|---|
| `real-device.mjs --no-clipboard` | Bridge-secret review: Windows clipboard history / cloud sync can retain the per-run secret. |
| `real-device.mjs --open-edge` (Windows) | The runner opens the bridge in an Edge `--app` window itself; the secret is never typed, pasted or shown on screen. NOT_RUN on the laptop at freeze time (manual fallback unchanged). |
| `scripts/v6/reconcile-mutations.mjs` | Targeted mutants for the reconciled controls. |

Not changed (static review, recorded): red-team actuators read `ACTION_SPECS[a.type].req` after a truthiness check;
an inherited name throws inside the actuator's parser (red-team harness only, no Root commit). `requiredLevelOf`
(`src/v5/root/command.mjs:32`) reads `REQUIRED_LEVEL[a.type]` on the owner-side display path; not a Root commit path.
