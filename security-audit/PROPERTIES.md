# Which SafeBox properties are enforced, and which are environment assumptions?

## Enforced by the implementation, in the runs this audit actually executed

These are properties of the code under test, observed with mock keys and a mock ledger, inside a network namespace that could not open an external TCP connection. They are not properties of a deployed wallet.

**SSTP Authority and package logic (in process, `c256ffa` plus the `verifySlot` patch).** The existing unit tests passed 30/30 before this audit's extra tests, and 32/32 after, inside the namespace:

- A payment inside Purpose is signed once and is idempotent on `requestId`.
- Spending outside Purpose needs a bound, fresh, single-use owner approval.
- Budget counters move only forward.
- Maintenance refuses payments. FREEZE and recovery rotation still run.
- There is no app-callable policy setter. A permissive policy migration needs owner and recovery. A stale digest is refused.
- Update authorization respects the version floor.
- Reconciliation keeps settling payments the Authority already signed and fails closed when the ledger shows a transfer the Authority did not sign.
- Random request sequences in the property test did not decrease counters or exceed policy.
- Package bytes that do not match the manifest, a bad mode, a symlink slot, and a planted symlink inside a slot are rejected.
- The new race test: a symlink swapped in on the `statx` that the old code used cannot be reported as a verified regular file.

**V2 in-process boundary (`8cd505b` plus the keygen patch, network namespace).** The suite's scripted cases denied prompt injection, impersonation, recipient and amount substitution, replay, duplicate execution, policy modification, freeze bypass, and the other named techniques, with the test's own assertion of no unauthorized mock-ledger effect. Crash recovery, single-use capabilities under a six-process race, and forged unfreeze statements were in that same passing run. This is the in-process Sensitive Zone and mock ledger. It is not the OS-isolated deployment.

**Root action names (handler patch only).** `toString` and `constructor` no longer commit a V5 transition. That property was false on `8cd505b` and true after `8778ce0`.

**File-path checks that were added.** Where a patch landed, a symlink at a key, credential, or owner-log path is refused, and a Gmail credential file mode other than owner-only is refused. Those checks did not exist, or did not apply to symlinks, on the frozen commits.

## Assumptions of this test environment, not properties the implementation enforces

- **No external network during tests.** Enforced by the namespace wrapper around the test process. The application does not contain that namespace. A run without the wrapper is not covered.
- **No real keys, funds, OAuth tokens, or mailboxes.** The tests construct synthetic Ed25519 material and strings such as `1//synthetic-refresh`. Passing tests say nothing about a real account.
- **No second user.** Symlink and mode tests run as one uid. They do not show that user A cannot read user B's files. Directory ownership in `layout.mjs` is a design claim. The OS-isolation test that would ask the kernel was skipped.
- **SSTP containment of publisher code.** Not implemented. The in-process Authority tests assume the Authority code is the code that runs, and that the attacker is a caller of that API rather than a replacement of the process.
- **V6 `LOCAL_GATE`.** The implementation documents that same-user code can use the gate key. This environment cannot re-check that, and no patch here changes it.
- **`HIGH_ASSURANCE`.** The implementation's stated behavior is to fail closed without an independent signer. This audit did not execute that path. Do not treat a green unit file on another branch as evidence that the mode was re-proven.
- **Mock ledger equals chain truth.** Tests that say "zero unauthorized ledger effect" mean the mock ledger object inside the process. They do not mean a NEAR node.
- **Independence of this report.** There was none. See `VERIFICATION.md`.

## Direct answer

The implementation enforces, and this audit re-observed, in-process authorization checks: Purpose and approval binding, monotonic budgets, FREEZE during maintenance, refusal of unsigned mock-ledger activity, package digest and symlink checks, and (only on the handler patch) rejection of prototype-named Root actions. It also enforces the new descriptor checks on the paths those patches cover.

It does not enforce OS isolation, publisher containment, same-user resistance of `LOCAL_GATE`, or the presence of an independent signer. Those remain assumptions you would have to add in the operating system or in hardware, or properties that fail closed because the hardware is absent. The network boundary used for these tests was the namespace around the test runner, not a property of SafeBox.
