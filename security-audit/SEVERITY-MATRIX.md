# Severity and confidence matrix

Classifications are exactly one of: `CONFIRMED_EXPLOITABLE`, `CONFIRMED_INVARIANT_VIOLATION`, `PLAUSIBLE_UNVERIFIED`, `FALSE_POSITIVE`, `KNOWN_RESIDUAL_RISK`, `OUT_OF_SCOPE`.

CodeQL rows are the 17 SSTP-scan results (the V6 scan is the same set without the installer line). Severity is for the operator of this prototype, not a CVSS score.

| ID | Rule and location | Class | Severity | Confidence | Patch branch |
|---|---|---|---|---|---|
| C1 | `js/file-system-race` `secure-transition/src/package/install.mjs:68` | CONFIRMED_EXPLOITABLE | Medium | High | `cursor/sstp-verifyslot-race-15f6` |
| C2 | `js/file-system-race` `src/v2/launch/keygen.mjs:13` | CONFIRMED_INVARIANT_VIOLATION | Medium | High | `cursor/v2-keygen-exclusive-15f6` |
| C3 | `js/file-system-race` `src/v2/launch/keygen.mjs:19` | CONFIRMED_INVARIANT_VIOLATION | Medium | High | `cursor/v2-keygen-exclusive-15f6` |
| C4 | `js/unvalidated-dynamic-method-call` `src/v2/launch/run-controller.mjs:39` | FALSE_POSITIVE | — | High | none |
| C5 | `js/unvalidated-dynamic-method-call` `src/v2b/launch/run-controller-rt.mjs:33` | FALSE_POSITIVE | — | High | none |
| C6 | `js/shell-command-injection-from-environment` `scripts/v2/run-isolated.mjs:31` | CONFIRMED_EXPLOITABLE | High if the root launcher runs from a metacharacter path | High for the pattern | `cursor/v2-shell-argv-15f6` |
| C7 | `js/indirect-command-line-injection` `scripts/v2b/run-redteam.mjs:38` | CONFIRMED_INVARIANT_VIOLATION | Low | Medium | `cursor/v2-shell-argv-15f6` |
| C8 | `js/file-system-race` `src/v6/notify/gmail.mjs:31` | CONFIRMED_EXPLOITABLE | Medium | High | `cursor/v6-gmail-cred-file-15f6` |
| C9 | `js/file-system-race` `scripts/v6/gmail-oauth-setup.mjs:61` | CONFIRMED_INVARIANT_VIOLATION | Medium | Medium | `cursor/v6-gmail-cred-file-15f6` |
| C10 | `js/http-to-file-access` `scripts/v6/gmail-oauth-setup.mjs:61` | FALSE_POSITIVE | — | Medium | path not taken from HTTP; creator hardened on the Gmail branch |
| C11 | `js/file-system-race` `src/v1/authz.mjs:57` | CONFIRMED_EXPLOITABLE | Medium | High | `cursor/v1-keyfile-nofollow-15f6` |
| C12 | `js/file-system-race` `src/v1/near/executor.mjs:21` | CONFIRMED_EXPLOITABLE | Medium | High | `cursor/v1-keyfile-nofollow-15f6` |
| C13 | `js/file-system-race` `src/v2/supervisor/owner.mjs:34` | CONFIRMED_EXPLOITABLE | Medium | High | `cursor/v2-owner-log-fd-15f6` |
| C14 | `js/log-injection` `scripts/v6/showcase.mjs` (line 73 V6 scan / 72 SSTP scan) | CONFIRMED_INVARIANT_VIOLATION | Low | Medium | `cursor/v6-showcase-log-line-15f6` |
| C15 | `js/bad-tag-filter` `src/v5/sim/scenarios.mjs:215` | FALSE_POSITIVE | — | High | none |
| C16 | `js/bad-tag-filter` `tests/v5/notify.test.mjs:40` | FALSE_POSITIVE | — | High | none |
| C17 | `js/file-system-race` `tests/v6/fixtures/fake-winbio-helper.mjs:7` | FALSE_POSITIVE | — | High | none |
| X1 | Prototype action dispatch, V3/V4/V5 `HANDLERS[type]` (not a CodeQL row) | CONFIRMED_EXPLOITABLE | High | High | `cursor/root-handler-own-property-15f6` |
| R1 | SSTP has no OS isolation and no containment of a malicious publisher | KNOWN_RESIDUAL_RISK | High as a deployment gap | High (documented, and not implemented in the tree) | none |
| R2 | V6 `LOCAL_GATE` same-user signing | KNOWN_RESIDUAL_RISK | High against same-user code | This audit did not re-run the hardware probe | none |
| R3 | `HIGH_ASSURANCE` with no independent signer | KNOWN_RESIDUAL_RISK | The mode is fail-closed; the missing signer is the residual | Fresh execution NOT_RUN | none |

## CodeQL classification counts (C1–C17)

| Class | Count |
|---|---|
| CONFIRMED_EXPLOITABLE | 6 |
| CONFIRMED_INVARIANT_VIOLATION | 5 |
| FALSE_POSITIVE | 6 |
| PLAUSIBLE_UNVERIFIED | 0 |
| KNOWN_RESIDUAL_RISK | 0 |
| OUT_OF_SCOPE | 0 |
| **Total CodeQL rows** | **17** |

X1 is an additional confirmed defect. R1–R3 are documented limits, not CodeQL rows. Counting those four with the CodeQL rows: exploitable 7, invariant violations 5, false positives 6, known residual risk 3.
