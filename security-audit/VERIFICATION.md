# Verification report

## Independence

There was one author. Auditor, boundary tester, patcher, and verifier were the same cloud agent. No second person and no second agent reviewed the patches before they were pushed. Re-running a test does not make the result independent. Do not read this file as an independent verification.

## What was executed

Network isolation for test runs was `unshare --user --map-root-user --net`, with loopback brought up only inside that namespace. Each isolated run printed `CONNECT_FAIL 101` (`ENETUNREACH`) for an external address before the tests. Git was not used inside that namespace.

| Check | Where | Result |
|---|---|---|
| Pre-fix `verifySlot` race | host, frozen `c256ffa` | FAIL, symlink left after success |
| Post-fix SSTP `tests/unit/*.spec.mjs` | network namespace | 32/32 pass, exit 0 |
| Mutant: drop `O_NOFOLLOW` in `verifySlot` | host | planted-symlink test fails |
| Pre-fix keygen public symlink and skipped public key | host, frozen `8cd505b` | canary overwritten; public key missing on re-entry |
| Post-fix `tests/v2/keygen-exclusive.test.mjs` | host, then the V2 suite inside the namespace | 5/5; V2 suite 52 pass |
| Mutant: private-key open without `O_NOFOLLOW` | host | private-symlink test fails |
| Pre-fix `toString` / `constructor` submit | host, frozen handlers | sequence 0→2, `ok: true` |
| Post-fix prototype tests | network namespace | 2/2 pass |
| Mutant: restore `HANDLERS5[a?.type]` | host | V5 prototype test fails |
| V3 `authority-attacks.test.mjs` and V5 `buffer.test.mjs` on the handler branch | host | pass (30 tests in that combined run, including the new ones) |
| Pre-fix shell template | host | marker file created |
| Post-fix `tests/v2/argv-exec.test.mjs` | network namespace | 3/3 pass |
| Mutant: `execFileSync('sh', ['-c', args.join(' ')])` | host | separator test fails |
| Pre-fix Gmail load, owner-key symlink, executor symlink, owner-log symlink | host, frozen `8cd505b` | permissive file and symlinks accepted; log view contained `forged` |
| Post-fix Gmail credential tests | network namespace | 2/2 pass |
| Existing `tests/v6/gmail.test.mjs` | host, fake fetch | 8/8 pass |
| Post-fix V1 key-file test | network namespace | pass |
| Existing `tests/v1/executor-verifier.test.mjs` | host | pass |
| Post-fix owner-log test | network namespace | pass |
| Showcase log unit test | host | pass |
| `tests/v2/os-isolation.test.mjs` on uid 1000 | host | 2 skipped (`OS isolation NOT VERIFIED`) |

Property tests that ran inside the network namespace are the SSTP unit property tests (random request sequences; random single-byte package corruption) as part of the 32. They passed on the installer patch. They do not cover the V6 handler patch; that branch got the V3 authority-attack file and the V5 buffer file on the host.

## Mutation

Full mutation campaigns (`secure-transition` `npm run mutations`, V5/V6 mutation scripts) were **NOT_RUN**.

Targeted mutants that were run:

| Mutant | Killed? |
|---|---|
| `verifySlot` without `O_NOFOLLOW` | yes, planted-symlink test |
| keygen private open without `O_NOFOLLOW` | yes |
| `HANDLERS5[a?.type]` restored | yes |
| `execArgv` rewritten as `sh -c` | yes |

No mutant was left in the tree. A marker file created in the workspace by the shell mutant was deleted and is not committed.

## What would weaken another boundary

The handler change rejects names that are not own properties. Declared actions still go through the same handlers. The V5 buffer tests and V3 authority-attack tests passed after the change. That is not a proof that every action type still works.

The installer change rejects symlinks at open time. Existing install/journal tests passed, including tamper, mode, and uid checks.

Keygen still uses synthetic Ed25519 keys and still publishes public keys. It refuses a group-readable private key, which the old skip path did not re-check.

No patch enables `HIGH_ASSURANCE`, real email, Testnet, or Mainnet.
