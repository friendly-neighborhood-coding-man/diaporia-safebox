# SSTP V0 evidence matrix (partial)

Source commit `3e580286816ba30710317e4fd871abcfa476e9a2`. Test run: 30/30 pass, exit 0 (`docs/evidence/secure-transition/unit-tests.tap`, `unit-tests.exit`). Environment: `environment.txt`. Test numbers below are the TAP line numbers.

## Labels

| Label | Meaning |
|---|---|
| VERIFIED_IN_PROCESS | A unit or property test exercises the logic in one process, as one OS user. It says nothing about OS isolation. |
| VERIFIED_VERIFIER_LAYER | The real `tuf-js` client (with the SSTP root gate) rejects or accepts the input. This is shown for the metadata-verification step only, not for an end-to-end update. |
| IMPLEMENTED_UNTESTED | Code exists; no test runs it. |
| NOT_IMPLEMENTED | No code. |
| NOT_RUN | The experiment needs components that do not exist, so it was not run. |
| BLOCKED | Needs hardware or environment that is not available (TPM). |

## 1. Components

| Component | Label | Evidence |
|---|---|---|
| Strict tar reader | VERIFIED_IN_PROCESS | tests 14–16, 18 (3,000-case corruption property, seeded) |
| Canonical manifest | VERIFIED_IN_PROCESS | tests 14, 17 |
| Slot installer + `verifySlot` | VERIFIED_IN_PROCESS (as root; ownership/permission checks are file-metadata checks, not access control) | tests 10–12 |
| Journal | VERIFIED_IN_PROCESS | test 13 |
| Release Metadata Verifier (tuf-js + root gate) | VERIFIED_VERIFIER_LAYER | tests 19–30 |
| Fetcher `mirror()` | VERIFIED_IN_PROCESS (used by every verifier test against a local HTTP server; it verifies nothing by design) | tests 19–30 |
| Publisher repo builder | VERIFIED_IN_PROCESS (as a fixture) | tests 19–30 |
| Authority logic | VERIFIED_IN_PROCESS | tests 1–9 |
| MOCK ledger class | VERIFIED_IN_PROCESS | tests 1, 3, 7–9 |
| Authority daemon, ledger daemon, IPC transport | IMPLEMENTED_UNTESTED | — |
| Witness logic and daemon | IMPLEMENTED_UNTESTED | — (test 6 uses witness-shaped signatures produced by the test, not the Witness class) |
| Fault-injection hooks (`crashPoint`, `ioFault`) | IMPLEMENTED_UNTESTED | — never triggered |
| Transition controller, A/B activation, rollback, launcher, OS users, network namespace, reference app, A/B/C harness | NOT_IMPLEMENTED | — |
| TPM / measured launch | BLOCKED | `environment.txt`: `tpm=none` |

## 2. Properties

| Property | Label | What exactly was shown | Tests |
|---|---|---|---|
| Unsigned / below-threshold / wrong-key metadata rejected | VERIFIED_VERIFIER_LAYER | tuf-js rejects empty signatures and 1-of-2 targets signatures | 20, 21 |
| Tampered package bytes under valid metadata rejected | VERIFIED_VERIFIER_LAYER | hash mismatch and length overrun both rejected | 22 |
| Metadata rollback rejected | VERIFIED_VERIFIER_LAYER | after seeing release 3, replaying release-2 metadata gives `TUF_ROLLBACK` | 23 |
| Expiry enforced offline | VERIFIED_VERIFIER_LAYER | expired timestamp and expired targets rejected; a timestamp that expires between two offline verifications is rejected the second time | 24, 25, 27 |
| Mix-and-match rejected | VERIFIED_VERIFIER_LAYER | current timestamp + snapshot with old targets rejected | 26 |
| Withheld metadata or target rejected | VERIFIED_VERIFIER_LAYER | missing target, empty snapshot | 27 |
| Root rotation needs owner approval | VERIFIED_VERIFIER_LAYER | a correctly cross-signed rotation is refused unless its exact SHA-256 is approved; plain TUF accepts it; a rotation not signed by the old root is refused by plain TUF too | 29, 30 |
| Owner approval of the root digest is enforced by the Authority quorum (owner + recovery) | VERIFIED_IN_PROCESS | `APPROVE_UPDATE_ROOT` with owner alone gives `OWNER_QUORUM_NOT_MET` | 5 |
| The verifier and the Authority are wired together (approved digests flow from Authority to verifier) | NOT_IMPLEMENTED | the tests pass the digest list by hand | — |
| Package integrity, structure and closed manifest | VERIFIED_IN_PROCESS | §1 above | 14–18 |
| Install destination allow-list, symlink escape, re-hash after install | VERIFIED_IN_PROCESS | | 10–12 |
| Version floor on update authorization | VERIFIED_IN_PROCESS | `AUTHORIZE_UPDATE` at version ≤ floor refused; floor raised only by `completeTransition` | 6 |
| Owner-approval binding, expiry, epoch, single use | VERIFIED_IN_PROCESS | | 2 |
| Payment idempotency on requestId | VERIFIED_IN_PROCESS | | 1 |
| Budget never restored; counters monotonic | VERIFIED_IN_PROCESS | 400-step seeded random sequence: nonce, spent, epoch and consumed-nonce count never decrease; spent ≤ budget; no settled tx outside Purpose; no requestId settled twice | 3, 9 |
| Payments refused during maintenance; FREEZE and recovery rotation accepted during maintenance; revoked owner key refused | VERIFIED_IN_PROCESS | | 4 |
| Settlement continues during maintenance and is reconciled | VERIFIED_IN_PROCESS | the ledger settles a payment broadcast before maintenance; reconcile marks it settled, rebroadcasts a signed-but-never-delivered payment exactly once, and the second reconcile settles it; 2 ledger txs total | 7 |
| Fail closed on ledger activity the Authority never signed | VERIFIED_IN_PROCESS | anomaly injected into ledger state (no signing); reconcile freezes and enters safe hold | 8 |
| Ending maintenance needs reconciliation + a valid witness signature bound to transition, policy and release | VERIFIED_IN_PROCESS | wrong key, wrong release and wrong transition id are refused | 6 |
| Application cannot read the account key / modify Authority, controller or witness state | NOT_RUN | no OS separation exists; in the tests everything runs as root | — |
| Malicious publisher code is contained | NOT_RUN | | — |
| A/B activation, crash recovery, rollback without financial rollback | NOT_RUN | | — |
| Network isolation during transition | NOT_RUN | | — |

## 3. U01–U16: original predictions (unchanged from `THREAT-MODEL.md` §7) and current status

The predictions are copied verbatim from the threat model. None is changed. "Status" says what, if anything, was tested. No A/B/C comparison was run, so the prediction columns remain untested as architecture results.

| ID | Prediction A | Prediction B | Prediction C | Status at `3e58028` |
|---|---|---|---|---|
| U01 unsigned | reject | reject | reject | VERIFIED_VERIFIER_LAYER (tests 20, 21). Per-architecture: NOT_RUN |
| U02 tampered contents | reject | reject | reject | VERIFIED_VERIFIER_LAYER (test 22) + manifest/tar layer VERIFIED_IN_PROCESS (17, 18). Per-architecture: NOT_RUN |
| U03 old signed version | accept (no floor) | reject (floor) | reject (floor) | Partial. Metadata rollback: VERIFIED_VERIFIER_LAYER (23). Old version still listed by a current release: only the Authority floor check is VERIFIED_IN_PROCESS (6); the end-to-end path and Baseline A's acceptance are NOT_RUN |
| U04 expired or mixed metadata | reject | reject | reject | VERIFIED_VERIFIER_LAYER (24–27). Per-architecture: NOT_RUN |
| U05 compromised server | reject | reject | reject | VERIFIED_VERIFIER_LAYER for replace, replay, mix, withhold, truncate-to-empty and freeze (22, 23, 26, 27). Interrupted downloads and delivery timing: NOT_RUN |
| U06 malicious signed code | FAIL (steals) | FAIL (steals) | contained; activation possible if owner approves | NOT_RUN |
| U07 key access | FAIL | FAIL | blocked by uid | NOT_RUN |
| U08 Purpose / limits | FAIL | FAIL | refused by Authority | Authority logic: no app-callable policy setter, quorum rules VERIFIED_IN_PROCESS (5). Containment of a candidate: NOT_RUN |
| U09 disable verification | FAIL | FAIL | refused | NOT_RUN (witness untested; controller absent) |
| U10 network during isolation | connects | blocked | blocked | NOT_RUN |
| U11 crash | not recoverable in place | recovers | recovers | NOT_RUN (journal torn-tail handling VERIFIED_IN_PROCESS, test 13, but no controller recovers from it) |
| U12 replay after rollback | FAIL if state rolls back with code | holds only if the app does not rewrite state | holds | Partial. Owner-approval replay and requestId reuse refused by the Authority: VERIFIED_IN_PROCESS (1, 2). Rollback: NOT_RUN |
| U13 pending/settled across switch | reconcile ambiguity | ok | ok | Partial. Settlement during maintenance + reconcile VERIFIED_IN_PROCESS (7). Version switch: NOT_RUN |
| U14 replace updater | FAIL | FAIL | blocked | NOT_RUN |
| U15 root rotation | accepted (plain TUF) | refused (owner pin) | refused | VERIFIED_VERIFIER_LAYER for both behaviours (29): plain TUF accepts, the SSTP gate refuses. Per-architecture: NOT_RUN |
| U16 concurrency | undefined | serialized | serialized; FREEZE always wins | Partial. Second `beginMaintenance` refused and FREEZE accepted during maintenance, sequentially in one process (4). True concurrency: NOT_RUN |

No prediction has been falsified by the tests run. U15 Baseline A ("accepted by plain TUF") was confirmed at the verifier layer.
