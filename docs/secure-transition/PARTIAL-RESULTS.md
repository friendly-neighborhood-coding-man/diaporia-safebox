# SSTP V0: partial results and closeout

**READY_FOR_OPERATOR_REVIEW — SSTP V0 PARTIAL EVIDENCE**

- Branch `experiment/secure-transition-v0`, based on the frozen V6 `bf7403d`.
- Source commit tested: `3e58028`. Implementation stopped by the operator on 2026-11-14 at 15:50Z. This closeout adds documentation and evidence only, with no code changes.
- Disposable cloud container, MOCK keys, MOCK ledger. No funds, no Testnet or Mainnet, nothing on the operator's machine. PR #13, PR #15 and the issue #14 branch are untouched.

## 1. Two separate findings

**Finding 1 (supported by tests).** The selected verification and authorization logic behaves as specified, in process: 30/30 unit and property tests (`docs/evidence/secure-transition/unit-tests.tap`, exit 0).

**Finding 2 (not established).** These results do **not** show that SafeBox can safely execute arbitrary publisher-signed code without exposing protected assets. Nothing tested here separates the code being installed from the account key, the policy state, the updater or the witness. Every component ran as root in one process.

The research question — can SafeBox reduce the need to trust its own publisher during updates? — is therefore **unanswered**. The tests show that the checks an independent Authority would apply are correct. They do not show that such an Authority can be kept independent of the application.

## 2. What the current results demonstrate

**TUF.** The real `tuf-js` 6.0.2 client, fed offline from an untrusted spool with a locally persisted trust state, rejects:

- unsigned metadata and metadata signed below the threshold;
- package bytes that do not match signed metadata (hash or length);
- replayed older metadata after newer metadata was seen;
- expired timestamp or targets metadata, with no offline exemption, including a timestamp that expired after an earlier successful verification;
- mixed metadata from two releases;
- withheld targets and snapshots.

All of this is the TUF library working as designed. SSTP's own contribution at this layer is wiring, an error taxonomy, and a requirement that each target declare a version. This is verifier-layer evidence only: no update was installed or activated as a result of any of these checks. The prototype is **not** claimed to be TUF- or Uptane-compliant as a system.

**Owner-approved root rotation.** A rotation that the old root keys correctly cross-signed is accepted by plain TUF. That is the Baseline A prediction, now confirmed at the verifier layer. The SSTP root gate refuses it unless the new root's exact SHA-256 is on an owner-approved list. Separately, the Authority accepts an `APPROVE_UPDATE_ROOT` command only with owner + recovery signatures. The two halves are **not wired together**: the tests pass the approved list to the verifier by hand.

What this means: a publisher who holds the root keys cannot silently move the client to new keys, provided the approved list really comes from the Authority and the verifier really runs outside the publisher's code. Neither condition was tested.

**Package integrity.** The tar reader and manifest reject every structural attack in the test list: symlinks, hardlinks, devices, traversal, absolute paths, setuid modes, duplicates, file-as-directory, size bounds, checksum errors, truncation, trailing data, non-canonical manifests, unknown manifest fields, extra or missing files and digest mismatches. A seeded property test applied 3,000 random single-byte corruptions. It never produced an accepted package whose manifest or contents differed. The installer refuses non-allow-listed or symlinked destinations, removes planted symlinks before writing, and detects tampering after install.

**Replay protection.** Inside the Authority:

- an owner approval is bound to `{requestId, to, amount}`, the epoch and an expiry, and its nonce is consumed once;
- reusing a requestId with different terms is refused, and the same terms return the same txid;
- the budget is never restored, and nonce, spent, epoch and consumed-nonce counters never decrease (400-step property run).

Replay **after an application rollback** was not tested, because there is no rollback.

**Maintenance behaviour.** In maintenance the Authority refuses payments, refuses a second transition, and still accepts FREEZE and recovery-key owner rotation. After rotation, the revoked owner key is refused. The MOCK ledger keeps settling while SafeBox is in maintenance: a payment broadcast before maintenance settled during it. This confirms by test that maintenance does not assume external settlement has stopped.

**Mock-ledger reconciliation.** Reconcile marks payments settled from the ledger and rebroadcasts the identical signed tx for a payment the ledger never saw. The rebroadcast happens once; the next reconcile settles it, and the ledger holds exactly two txs. If the ledger shows a tx the Authority never signed, reconcile freezes the account and enters safe hold. Ending maintenance requires reconciliation and a witness signature bound to the transition id, the current policy digest, the epoch and the owner-authorized release. Signatures with a wrong key, wrong release or wrong transition id are refused.

## 3. What has NOT been demonstrated

None of the following has been demonstrated, at any level:

- OS-enforced isolation of any kind: uid, file permissions, process separation or network namespace;
- containment of malicious publisher code;
- an A/B transition, activation or rollback;
- crash recovery: no controller exists, and the fault-injection hooks were never triggered;
- an end-to-end A/B/C comparison, or any of the research measurements in the mission brief §9;
- the Authority, ledger and witness running as daemons, and the IPC transport;
- the Witness class;
- the state-machine, fault-injection, mutation-testing, clean-room and independent-review requirements;
- resistance to arbitrary native code, OS or kernel compromise, privileged-component compromise, or hardware attacks. These were never in the verifiable scope of this milestone.

Per-architecture answer to *"Can a malicious publisher with a valid release signing key install software that steals owner funds?"*:

| Architecture | Answer |
|---|---|
| Baseline A | NOT_RUN |
| Candidate B | NOT_RUN |
| Candidate C | NOT_RUN |

What the design implies, untested: if application code and the account key share an OS security boundary, which is the V6 LOCAL_GATE situation, a malicious signed update holds what the process holds, and the Authority's checks do not help. Changing that requires the key and the policy state to sit behind a boundary the application cannot cross. That boundary was not built or measured here.

## 4. Observations from writing this closeout (not fixed, by instruction)

1. `package.json` lists `test:os`, `campaign`, `demo` and `mutations` scripts whose files do not exist. Only `npm test` works.
2. In test 30, one statement (`repo.keys.root = repo.keys.root.map(...)`) is dead code, overwritten on the next line. The test's assertion is unaffected.
3. The journal's hash chain detects corruption and torn writes only. A writer who can rewrite the file can rebuild a valid chain. Protecting the journal depends on file permissions that were never set up.
4. Inside Purpose, the Authority signs without owner involvement. Any application version, malicious or not, can spend up to the budget to allow-listed recipients. This is a design residual (INHERENT_RESIDUAL), not a test failure.
5. The Authority accepts signed owner commands on its application interface. They are signature-checked, but an application could withhold or delay them.

## 5. Safety interruptions (factual record)

Two of the assistant's responses were stopped by a safety classifier during this work. In both cases the rest of the response was withheld, and tool calls that had not finished did not run.

1. **Before 15:19Z, 2026-11-14.** The response in which the witness module was written (the file write completed). The adversarial part of the experiment was the next planned step. The operator then approved a reduced scope (15:19Z): benign request clients only, with no executable malicious payloads.
2. **Between 15:19Z and 15:50Z, 2026-11-14.** The response that followed the commit of the 30 unit tests (`3e58028`), as work moved to the transition controller and isolation launcher. No controller or launcher code was written.

No cause is inferred. By the operator's instruction (15:50Z), no further version of the controller or launcher work was attempted, and there was no attempt to identify or work around the trigger.

## 6. Recommended next research questions

1. Can the account key and policy state be held behind a separation that is enforced outside the application's control (a separate device, hardware-backed key store or separately administered host), and what is the minimum interface the application needs?
2. Given that separation, does the Authority logic tested here (bound approvals, monotonic counters, reconciliation, owner-gated root rotation) reduce accepted compromised-publisher actions compared with an in-process wallet, measured on the same request set?
3. How should approved root digests and version floors flow from the Authority to the verifier, so that a compromised updater cannot substitute them?
4. What is the residual from in-Purpose spending by a malicious but owner-approved release? Should Purpose budgets reset, or tighten automatically, across a version change?
5. Which parts of the transition (activation, rollback, crash recovery) can be specified and model-checked before any execution environment is built?
6. Would an independent reviewer accept the verifier-layer results as stated here? An independent review of this partial milestone has not been done.
