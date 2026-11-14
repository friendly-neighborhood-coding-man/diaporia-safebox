# SafeBox V6 final submission candidate (reconciliation of PR #28)

**Status: READY_FOR_FINAL_OWNER_RECORDING_REVIEW** (see outstanding conditions at the end). Not a production release.
No merge, no deployment, no real funds, no blockchain transaction.

- **Frozen code: `a8ce01840d79166403aec159c8c05e70bd916721`** on `integration/v6-final-candidate` (parent `60cfd20`,
  the PR #26 freeze, unmodified). Commits after `a8ce018` on this branch are documentation and evidence only.
- Track C (never applied to the candidate): `security-research/v1v2-legacy-hardening` (PRs #19, #21, #23, #24 + fixes),
  `security-research/sstp-pr27-verification` (SSTP evaluation, on `d6172ec`).
- CodeQL audit branch: `security-audit/codeql-v6-final` (= `a8ce018` + the disposable audit workflow).

## What changed against 60cfd20

| Severity | Finding | Present at 60cfd20? | Fix | Evidence |
|---|---|---|---|---|
| **HIGH** | Root action dispatch: inherited `Object.prototype` names (`toString`, `constructor`, ...) and any function planted on `Object.prototype` dispatch as handlers and commit a Root transition with no approval. V3 and V4 commit 2 names, V5 and V6 commit 8; a planted function sets epoch 1 -> 99 in all four | **yes** (reproduced) | PR #20 own-property dispatch (V2 zone, V3, V4 + V3 passthrough, V5; V6 via V5) | `root-dispatch-60cfd20.json` vs `root-dispatch-a8ce018.json`; `tests/v3/prototype-action.test.mjs` fails 4/4 on 60cfd20 |
| **MEDIUM** | HOLD_EXPIRE / RAPID_USE_EXPIRE (evidence-free) accept `holdId`/`grantId` = `constructor` etc. and commit (seq, head, nonces advance) with no approval; changes no authority | **yes** (found by the independent review) | `own()` for every request-supplied id lookup in the V5 Root | `tests/v5/prototype-ids.test.mjs` fails 2/2 without the fix; delta review fuzz 1764 attempts, 0 commits |
| LOW | Gmail credential file mode not checked (#22) | yes | #22 merged into #26's loader: 0600 on POSIX, exclusive-create writer with field validation | `tests/v6/gmail-cred-file.test.mjs` |
| LOW | Showcase viewer: kind/labels not escaped (constants) | yes | escape all fields | `tests/v6/showcase-log-reconcile.test.mjs` |
| LOW | `--demo` copied the bridge secret to the Windows clipboard | yes | clipboard is opt-in (`--clipboard`); new `--open-edge` | runbook |

The 60cfd20 summary's sentence "No HIGH or MEDIUM finding is open in the V6 candidate" was **wrong**: the HIGH and the
MEDIUM above were present there. Do not record on 60cfd20.

Unchanged: fingerprint gate, payment approval, Vault, FREEZE, HOLD_RELEASE and recovery logic (both reviews checked).
The only behaviour changes for real input: a non-string action type or id is refused (stricter).

Patch decisions: RECONCILIATION-LEDGER.md. Evidence and NOT_RUN inventory: EVIDENCE-INDEX.md. Recording:
RECORDING-RUNBOOK.md. SSTP: SSTP-PR27-EVALUATION.md (PARTIAL EVIDENCE, separate).

## Residual risks (unchanged labels)

- **P0.1 LOCAL_GATE: INHERENT_RESIDUAL.** A same-user process can sign with the Windows gate key. HIGH_ASSURANCE fails
  closed (ISOLATED_GATE_KINDS is empty). Independent signer: BLOCKED_OPERATOR_HARDWARE. Fingerprint-only =
  FINGERPRINT_ONLY_LOCALLY_VERIFIED (WinBio MATCH + gate-key signature + post-MATCH Yes); not hardware attestation.
  Windows Hello UV alone may be a PIN.
- **Interface-level only.** The attack denials show that the SafeBox interfaces refuse; they say nothing about native code,
  OS or kernel compromise, launcher compromise or hardware attacks. The attacker side is simulated.
- **NOT_RUN:** V6 OS isolation, tenant isolation, P1.5 independent risk context, NEAR Testnet, Windows CI, advisory-db
  audit, P2.10/11/12. The V2/V3 Linux OS-principal tests ran in this cloud container as root; that is not V6 OS isolation.
- **Mutation survivors (V6 script): 74/76.** The same two redundant nonce checks sit behind the PRIMARY KEY. One V5
  survivor ("Verifier: flow from the vault row instead of signed evidence") **also survives at 60cfd20** (pre-existing test gap,
  not from this change; it was caught at 6586a14).
- Gmail on Windows: the file relies on the profile ACL (no O_NOFOLLOW, no POSIX mode). Under WSL `/mnt/c` the new
  0600 check refuses the file (use native Windows Node).
- Not converted (LOW, behind approvals or refusing checks): remaining bracket lookups such as `src/v5/root/chain.mjs`
  `newHold` and CONTEST holdIds, `holds.mjs`, `command.mjs`, `console.mjs:261`. Red-team actuators `ACTION_SPECS[a.type].req`
  throw (harness only). HOLD_EXPIRE/RAPID_USE_EXPIRE on a real expired hold or grant can be repeated by design (journal growth only).
- `--open-edge`: NOT_RUN on Windows. The secret is on the cmd/msedge command line (same-user residual), and can persist in
  process-creation audit logs and Edge history; it is useless after the run.
- SSTP: PARTIAL EVIDENCE. PR #27 leaves the directory swap-and-swap-back race open; OS isolation NOT_IMPLEMENTED.

## Outstanding conditions before the final take

1. The owner reviews this candidate and the runbook (READY_FOR_FINAL_OWNER_RECORDING_REVIEW).
2. Laptop preparation per runbook section 0 (new worktree at `a8ce018`, interactor build, helper hash).
3. First Windows use of `--open-edge`; if no window appears, use the documented pause-and-open fallback.
4. The real take needs the owner at the laptop (fingerprint touches). Until it runs, real-device evidence for
   `a8ce018` is NOT_RUN. The last real-sensor run is run 12 on `1ff616b`; the gate, Vault and verifier code is unchanged since,
   and the Root changed only in dispatch and id lookups.
