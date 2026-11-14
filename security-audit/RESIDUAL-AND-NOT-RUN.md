# Residual risk and NOT_RUN

## Residuals that these patches do not close

1. **SSTP OS isolation is not implemented.** The controller, launcher, OS users, and A/B/C harness are still absent. In-process verifier and Authority tests do not show that a malicious publisher is contained. None of the patches claim otherwise.
2. **After a successful `verifySlot`, a same-user writer can replace the slot.** The race between `lstat` and `readFile` is closed. The lack of a uid boundary is not.
3. **V6 `LOCAL_GATE` same-user signing** remains the documented residual. A same-user process that can use the gate key and satisfy the other factors in that mode is outside every patch in this audit.
4. **`HIGH_ASSURANCE` still fails closed** when no independent signer is present. No patch adds a signer or flips the mode.
5. **Same-user read of mode `0600` files.** O_NOFOLLOW and mode checks stop symlink follow and group/other read. They do not stop the owner of the file.
6. **Gmail token storage is intentional** after state and scope checks. A same-user reader of the terminal can still see the loopback state. The setup script's live OAuth path was not run.
7. **V2-B still uses a shell** to chain mounts inside `unshare`. Arguments pass through `shellSingleQuote`. The quoting test passed. A mistake in a future unquoted interpolation would not be caught by the `find` test.
8. **General-zone RPC results** are still data from an untrusted peer. The controller false positive does not mean those results are trustworthy.
9. **Housekeeping actions that are real own properties** can still be submitted without the approval a different action would need. Only prototype names were closed.
10. **Test-fixture WinBio helper** still has a check-then-read. It is not on a production path. Left unchanged.

## NOT_RUN

| Item | Why |
|---|---|
| GitHub code-scanning API | HTTP 403. Workflow logs were used instead. |
| Fresh `LOCAL_GATE` laptop / TPM probe | No operator hardware in this environment. |
| Fresh `HIGH_ASSURANCE` suite | Not re-executed. |
| SSTP OS launcher, uid separation, malicious-publisher containment | Not implemented. Not added. |
| Product OS-isolation tests (`tests/v2/os-isolation.test.mjs`) | Skipped without real root. The user-namespace uid 0 attempt is not a result. |
| `scripts/v2/run-isolated.mjs` and `scripts/v2b/run-redteam.mjs` as processes | They require real root, `useradd`, and `setpriv`. |
| Gmail OAuth browser dance and any call to Google | Forbidden by the brief. Fake tokens and a fake `fetch` only. |
| Showcase browser runner | Starts a GUI browser. Only the log-line helper was tested. |
| Mainnet, Testnet, funded transactions | Not performed. |
| Full mutation suites and a clean-room second reviewer | Not run. See `VERIFICATION.md` for the four single mutants. |
| Windows CI, npm audit remediation, provenance, tenant isolation | Out of this review's edits. `npm ci` reported existing advisories and did not change lockfiles. |
| Scheduler race on `owner.mjs` without a planted symlink | Not won. The symlink case was run. |
| End-to-end pre-fix execution of `gmail-oauth-setup.mjs` | NOT_RUN. |
| V6 full root suite (571 tests cited by PR #15) | NOT_RUN in this audit. |
| Deployment, merge, enabling `HIGH_ASSURANCE` or real email | Not done. |

## Isolation result

**PASS for the test runtime's network namespace.** `unshare -n` alone was not permitted. `unshare --user --map-root-user --net` was, and an external TCP connect failed with `ENETUNREACH` on every isolated run recorded above.

**NOT a pass for SafeBox OS isolation.** The product's own OS tests did not run.
