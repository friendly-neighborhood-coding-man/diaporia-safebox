# CodeQL triage for the SafeBox submission freeze (2026-11-14)

Scope: CodeQL Advanced, `javascript-typescript`, `security-extended`, on disposable audit branches only. The frozen
source branches (PR #13 `bf7403d`, PR #15 `8cd505b`, PR #16 `c256ffa`) were not modified. Patches live on separate
branches and were re-scanned on their own audit branches.

| Track | Audit branch (scan) | Base | Result |
|---|---|---|---|
| V6 hardening (PR #15) | `security-audit/codeql-v6-hardening` | `8cd505b` | 16 warnings, 0 errors |
| SSTP V0 (PR #16) | `security-audit/codeql-sstp-v0` | `c256ffa` | 17 warnings (the same 16 + 1 SSTP), 0 errors |
| V6 patch | `security-audit/codeql-v6-fix` | `security-fix/v6-codeql` `e658805` | see "Re-scan" below |
| SSTP patch | `security-audit/codeql-sstp-fix` | `security-fix/sstp-verifyslot` `1952768` | see "Re-scan" below |

Exploitability scale used here: **CONFIRMED** (a realistic attacker in the documented threat model gains something),
**WEAKNESS** (a real pattern defect; exploiting it needs access that already defeats the control, or the impact is
cosmetic), **NOT_EXPLOITABLE** (the flagged flow cannot carry attacker data, or the operation is atomic), **TEST_ONLY**.

## V6-owned findings (fixed on `security-fix/v6-codeql`)

| # | Rule | Location (8cd505b) | Analysis | Verdict | Fix |
|---|---|---|---|---|---|
| V6-1 | js/file-system-race | `src/v6/notify/gmail.mjs:31` | `statSync(path)` then `readFileSync(path)`. No security decision sits between the two calls (the stat was an existence probe), so the race grants nothing; but a symlink or FIFO at the path was followed. The file is in the owner's own profile. | WEAKNESS, LOW | One `openSync` (O_NOFOLLOW where the OS has it), `fstat().isFile()`, read from the same fd. Test CQ-1. |
| V6-2 | js/file-system-race | `scripts/v6/gmail-oauth-setup.mjs:61` | `existsSync(out)` then `writeFileSync(out, token, {mode:0600})`. A file or symlink planted in between would be followed/overwritten, and `mode` does not apply to an existing file. Needs write access to the chosen output directory (owner's profile): same-user, one-shot operator script. | WEAKNESS, LOW | Exclusive create `O_CREAT|O_EXCL|O_NOFOLLOW`, 0600; the early `existsSync` stays as a friendly refusal. |
| V6-3 | js/http-to-file-access | `scripts/v6/gmail-oauth-setup.mjs:61` | Writing the Google token response to disk is the script's purpose; the scope is checked to be exactly `gmail.send` first and the file is outside the repo. | BY DESIGN | None (covered by V6-2's safer write). |
| V6-4 | js/log-injection | `scripts/v6/showcase.mjs:73` | Event text includes request-derived strings (AI memo, mail subject, hold reason). CR/LF or ANSI sequences could forge or recolour a line in the terminal that the submission video shows next to the Owner Console. No authority is affected; the risk is a misleading recording. | WEAKNESS, LOW (demo integrity) | `src/v6/common/term.mjs` `termSafe`: CR/LF, C0/C1 controls, ANSI ESC, U+2028/2029 and bidi overrides rendered as `\uXXXX`/`\n`. Also applied to `scripts/v6/real-device.mjs` (same pattern, not flagged). Test CQ-2. |
| V6-5 | js/file-system-race | `tests/v6/fixtures/fake-winbio-helper.mjs:7` | Test fixture emulating the gate helper; never used outside tests/selftest. | TEST_ONLY | None |

## SSTP finding (fixed on `security-fix/sstp-verifyslot`)

| # | Rule | Location (c256ffa) | Analysis | Verdict | Fix |
|---|---|---|---|---|---|
| S-1 | js/file-system-race | `secure-transition/src/package/install.mjs:68` | `verifySlot` lstat-checks each entry (not a symlink, not group/world writable, owner) then `readFileSync(p)` by path. A writer who can swap the entry between the two calls can put a symlink to a byte-identical file in place: the digest matches, the symlink check already passed, and the slot is accepted while containing a re-pointable symlink. The precondition (write access to an inactive slot) is exactly what SSTP's unimplemented OS isolation is meant to deny, so in the current partial build it is a defence-in-depth gap. | CONFIRMED (in the SSTP threat model), MEDIUM | `readCheckedFile`: one `open(O_RDONLY|O_NOFOLLOW|O_NONBLOCK)`, fstat must be the same dev/inode as the lstat, the regular-file / mode / owner checks are repeated on the fd, bytes are read from that fd. New race test (symlink swap, inode swap, FIFO swap). SSTP stays PARTIAL EVIDENCE. |

## Inherited V1 to V5 findings (left unchanged: frozen legacy code, not in the V6 demo path)

| # | Rule | Location | Analysis | Verdict |
|---|---|---|---|---|
| L-1 | js/file-system-race | `src/v2/launch/keygen.mjs:13`, `:19` | `existsSync` then `writeFileSync(..., { flag: 'wx' })`. `wx` is O_CREAT|O_EXCL: the create is atomic and does not follow a planted symlink; the race can only make keygen fail. Runs as the owning principal inside its own 0700 directory with SYNTHETIC keys. | NOT_EXPLOITABLE |
| L-2 | js/file-system-race | `src/v1/authz.mjs:57` (`loadOwnerSigner`) | `statSync` mode check (refuse group/world-readable) then read by path. Swapping needs write access to the key's directory, which already lets the attacker replace or read the owner key file outright; the race only skips the "too permissive" mode check. V1 code, not used by V6. Not re-analysed further for this freeze. | WEAKNESS, LOW (V1) |
| L-3 | js/file-system-race | `src/v1/near/executor.mjs:21` | Same pattern for the V1 NEAR executor key (Testnet path, never run live). | WEAKNESS, LOW (V1) |
| L-4 | js/file-system-race | `src/v2/supervisor/owner.mjs:34` | Incremental reader of an append-only log written by the same OS principal; size then read. No security decision on the stat. | NOT_EXPLOITABLE |
| L-5 | js/unvalidated-dynamic-method-call | `src/v2/launch/run-controller.mjs:39` | `waiting.get(m.id)` then call. `waiting` is a `Map` of resolvers created by the controller itself: an unknown id returns `undefined` (optional call), and no prototype method is reachable. | NOT_EXPLOITABLE |
| L-6 | js/unvalidated-dynamic-method-call | `src/v2b/launch/run-controller-rt.mjs:33` | Same as L-5. | NOT_EXPLOITABLE |
| L-7 | js/shell-command-injection-from-environment | `scripts/v2/run-isolated.mjs:31` | `sh -c "find ${ROOT}/src ..."` where ROOT is the script's own install path. Controlling it means controlling where the operator installed the code (already code execution). Root-only CI/operator script. | NOT_EXPLOITABLE (hygiene: prefer execFile) |
| L-8 | js/indirect-command-line-injection | `scripts/v2b/run-redteam.mjs:38` | CLI arguments of a root-only operator script flow to `execFileSync` arguments (no shell). The operator is the only source. | NOT_EXPLOITABLE |
| L-9 | js/bad-tag-filter | `src/v5/sim/scenarios.mjs:215` | A case-sensitive regex in a V5 simulation **assertion** (`noHtml`) over outgoing mail text, not a sanitizer. The V5 notifier strips links/HTML separately; a missed `<SCRIPT>` would only weaken that report line. | NOT_EXPLOITABLE (test-quality note) |
| L-10 | js/bad-tag-filter | `tests/v5/notify.test.mjs:40` | Test. | TEST_ONLY |

Why legacy is not patched now: the submission freeze forbids redesign, these files are outside the V6 demo path, and
none of them is exploitable beyond access that already defeats the control. They stay listed as open LOW / hygiene
items.

## Re-scan after the patches (final round)

| Branch (scan) | Run | Results | Change vs baseline |
|---|---|---|---|
| `security-audit/codeql-v6-fix` = `60cfd20` + audit workflow | 43617748239 | 16 warnings, 0 errors | **Closed:** V6-1 `gmail.mjs:31` race, V6-4 `showcase.mjs` log injection. **Still reported, triaged:** `gmail-oauth-setup.mjs:65` race (the early `existsSync` is now only a friendly refusal; the write is O_CREAT/O_EXCL/O_NOFOLLOW, so the race cannot redirect it: NOT_EXPLOITABLE), `gmail-oauth-setup.mjs:67` http-to-file-access (BY DESIGN). **New, triaged:** `real-device.mjs:69` race on `.demo-bridge-url` (lstat, unlink only a regular file, then exclusive create without following symlinks: a planted file makes the run stop; NOT_EXPLOITABLE), `real-device.mjs:268` http-to-file-access (the runner writes JSON-encoded HTTP status codes of its own loopback gate server into its own evidence file; NOT_EXPLOITABLE). All 11 legacy and test-only findings unchanged. |
| `security-audit/codeql-sstp-fix` = `d6172ec` + audit workflow | 43617751244 | 17 warnings, 0 errors | **Closed:** S-1 `install.mjs:68`. **New:** `secure-transition/tests/unit/install-journal.spec.mjs:78` (the race test itself: TEST_ONLY). The other 16 are the inherited V6/legacy findings: this branch is based on PR #16, which predates the V6 patch. |
| (first patch round) `e658805` / `1952768` | 43616892232 / 43616895145 | 15 / 17 | superseded by the rows above |

## Independent review of the patches

Two rounds by a separate reviewer that was given the diffs, not this triage.
- Round 1 (`e658805`, `1952768`): **PASS_WITH_ISSUES**. One MEDIUM: the SSTP fix closed the file-level race but not
  the directory-level one (a subdirectory swapped for a symlink was still followed). LOWs: post-close `chmod` by path,
  invisible/bidi characters not escaped, a selftest leak check that could not fire, attack 01/07 checks too loose
  (attack 07's scanner visits were in fact getting HTTP 421 and never reached the page), `#t=` secret visible in the
  bridge page address bar, FIFO hang in the credentials loader.
- Round 2 (`60cfd20`, `d6172ec`): **PASS**. MEDIUM fixed with a documented residual (a swap and swap-back entirely
  between two checks, impossible to close without `openat`; needs attacker write access to the slot tree). All LOWs
  fixed or accepted (below).

Accepted LOW residuals: no `O_NOFOLLOW` on Windows for the credentials file (operator's own path);
the Windows clipboard keeps the per-run bridge link (dead after the run); Ctrl-C leaves `.demo-bridge-url` (0600, dead
secret); a reload of the bridge page needs the link again; witness slot paths must be canonical (fails closed);
SSTP `verifySlot` fails closed on Windows (SSTP is POSIX-only); U+180E not escaped (harmless).
