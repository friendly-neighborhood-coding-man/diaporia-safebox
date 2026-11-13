# SafeBox V4 recovery protocol (mission §3, §4, §5)

Code: `src/v4/root/chain.mjs` (handlers `RECOVERY_*`, `ORC_REPLACE`, `GOV_*`, `PARTICIPANT_LIVENESS_*`, `GUARDIAN_ROTATE`), `src/v4/ballot/ballot.mjs`, `src/v4/recovery/service.mjs`, `contract-v4/src/lib.rs`.
Tests: `tests/v4/r1-closure.test.mjs`, `tests/v4/r3-governance.test.mjs`, `tests/v4/ballot-integration.test.mjs`, `tests/v4/recovery-matrix.test.mjs`, `tests/v4/mutation-kills.test.mjs`, `contract-v4/src/tests.rs`.

## 1. Key-loss recovery (V3 rules kept, R-1 closed)

V3 paths stay: a **minority** loss (lost keys ≤ half of the baseline) is a RECOVERY_CHALLENGE that the surviving keys, one guardian quorum and one identity attestation complete; a **majority** loss is a RECONSTITUTION (emergency lockdown, two identity attestations, the reconstitution guardian quorum, 72 h window, every notification channel acknowledges) that retires all current credentials and starts a new epoch.

V4 adds:

| Rule | Value | Enforced by |
|---|---|---|
| RECONSTITUTE requires `RECOVERY_OWNER_AUTHORIZE` by an active ORC, verified at a trusted level, with `ownerAuth.caseDigest === case.digest` | the case digest commits to the lost set, the plan (credIds, roles, public keys) and plan metadata | `RECONSTITUTE`, `RECOVERY_OWNER_AUTHORIZE` |
| ORC authorization only after notifications were dispatched and before the deadline | `OWNER_AUTHORIZATION_BEFORE_NOTIFICATION`, `OWNER_AUTHORIZATION_AFTER_DEADLINE` | |
| A replan clears the ORC authorization and the consent levels and restarts the window | | `RECOVERY_REPLAN` |
| A minority RECOVERY_COMPLETE needs at least one consent at a trusted level, or an ORC authorization for this digest | `NO_TRUSTED_CONFIRMATION_IN_CASE` | `RECOVERY_COMPLETE` |
| Deadline | `deadline = openedAt + windowMs` (72 h) | |
| Expiry | anyone may expire a case that is unapproved at the deadline (majority, HOLD or impossible paths, or minority still unconfirmed), or any case at `deadline + 7 d` grace; lockdown released; outcome `EXPIRED_UNAPPROVED`; no authority change | `RECOVERY_EXPIRE` (housekeeping, not an authority change) |
| ORC cancel | the ORC cancels any open case (including during lockdown) | `RECOVERY_ORC_CANCEL` |
| Reattempt cooldown | 12 h after a failed (cancelled / expired) claim, keyed on the **subject holder**, so a new case ID does not help | `RECOVERY_REATTEMPT_COOLDOWN` |
| Claim budget | 3 failed claims per subject per 30 days | `RECOVERY_CLAIM_BUDGET_EXHAUSTED` |
| Burned plan keys | keys of a failed plan can never be proposed again | `PLAN_KEY_PREVIOUSLY_REJECTED` |
| Lockdown budget | claim-triggered lockdown ≤ 96 h per 30 days (worst case observed: 146 h across the budget window boundary, ≤ budget + one 72 h window) | |
| ORC-attested open | an open carrying one ORC intent is exempt from cooldown and claim budget (the V3 global 1 h case interval still applies) | `RECOVERY_OPEN` |
| ORC is never a payment / Purpose / freeze authority | ORC IDs are not V3 credentials; only ORC_REPLACE, owner-quorum membership and case actions accept them | |
| Protective actions of revoked keys (F-V4-01 / 01b) | a suspended survivor's own intent-bound consent counts; on completion, suspensions imposed only by revoked keys are reactivated and freeze holds placed only by revoked keys are dropped; the freeze lifts only when no other hold remains, never for a supervisor breach freeze; the consent / ORC screen lists all of it | `RECOVERY_CONSENT`, `liftProtectiveActionsOfLost` |

**INV-V4-01 / 02.** Silence is never consent: the only transitions that move authority in a majority case require an ORC intent bound to the case digest. Acknowledgements and elapsed time only gate timing.

**ORC loss.** If the ORC is lost, ORC_REPLACE needs the AMEND_MATRIX governance quorum (as AuthorizationIntents, at least one at a trusted level) plus the guardian quorum, the new ORC's proof of possession, an owner holder and an independent key, and no open case or lockdown; a majority loss together with the ORC loss is **unrecoverable by design** (see RESIDUAL-RISKS.md). A minority loss never needs the ORC as long as one surviving consent is at a trusted level.

### Legitimate owner ceremony (usability, §15)

`legitimateRecoveryV4` in `src/v4/recovery/sim.mjs` drives the ceremony the owner would see: open with the new device(s) → surviving devices consent (each shows the Root-derived plan key digests) → independent parties attest on their own devices → owner acknowledges on each channel → ORC authorizes the exact plan → completion. Measured in `docs/evidence/v4/recovery-matrix.md`:

| Loss | Outcome | Owner gestures / prompts | Independent signer interactions | Chain signatures | Latency |
|---|---|---|---|---|---|
| 1 or 2 keys (15 subsets) | RECOVERED | 8 / 5 | 3 | 10–11 | ~1 h (early completion with all acks) |
| 3 or 4 keys (15 subsets) | NEW_EPOCH | 10–11 / 7–8 | 5 | 11–12 | ~72 h |
| all 5 keys | RECOVERY_IMPOSSIBLE (lockdown released at expiry) | 5 / 5 | 1 | 2 | 72 h |

Gestures count physical confirmations including channel acknowledgements; prompts count trusted-path prompts; signatures are counted separately from human interactions.

## 2. Emergency participant replacement (R-3)

Procedures: `GUARDIAN_EMERGENCY_REPLACE`, `IDENTITY_VERIFIER_EMERGENCY_REPLACE`. Ordinary voluntary rotation stays `GUARDIAN_ROTATE` (outgoing guardian signs, AMEND_MATRIX quorum).

1. **Open** (`GOV_CASE_OPEN`, CRITICAL): approvals from **two distinct owner roles** among DAILY, ROOT, RECOVERY, ORC (FREEZE excluded; provisional credentials excluded), as AuthorizationIntents; no guardian or attestation evidence mixed in; no recovery case or lockdown open; personal profile only.
2. **Grounds and evidence**, per accused member, independent of the electorate:
   - COMPROMISE / MISCONDUCT: verdicts from `adjudicatorQuorum` = 2 distinct active adjudicators, each signed, bound to the account, chain, subject and subject key, unexpired; or, for COMPROMISE of a guardian, an equivocation proof (the member's own key signed both APPROVE and OBJECT for the same action).
   - UNAVAILABLE: a liveness ping open for 30 days without a pong (pings cannot be reset while open).
   - WITHDRAWAL: a statement signed by the member's own key.
3. **Replacements**: exactly 1:1, each with proof of possession bound to the case; new id, new key, new holder, independent of every existing participant, credential, ORC and adjudicator.
4. **Electorate** = active guardians + identity verifiers − accused − previously disqualified. An empty electorate fails (`EMERGENCY_ELECTORATE_EMPTY`); the condition is reported and authority stays unchanged.
5. **Notification** of every channel (`GOV_DISPATCH`), required before execution.
6. **Confidential ballots** (`GOV_BALLOT`): one per eligible voter, signed by its pinned key; ineligible voters, duplicates and late ballots are refused.
7. **Tally** (`GOV_TALLY`, signed by the enrolled tally key): APPROVED needs every eligible voter's ballot and the opening of every commitment to APPROVE (the Root re-checks each commitment, so the tally cannot fabricate an approval). REJECTED publishes no openings and is allowed once all voted or the 72 h vote window ended.
8. **Security delay** of 24 h after approval; the owner can cancel with the ORC alone or with the owner quorum (`GOV_CASE_CANCEL`).
9. **Execute** (`GOV_CASE_EXECUTE`): atomic 1:1 swap; COMPROMISE / MISCONDUCT disqualify the removed member forever; participant count unchanged (`QUORUM_FLOOR_CHANGED`) and never below the reconstitution quorum; epoch bump.
10. **Expiry**: a case that is not tallied within the vote window, or approved but not executed within delay + 7 d, expires without effect.

Governance cases never touch owner credentials, payments, the Purpose or freeze state (INV-V4-09); mutual exclusion with recovery cases prevents participant churn during a recovery.

**INV-V4-03.** A malicious guardian majority cannot replace anyone on its own: opening needs two owner roles and independent evidence; the accused cannot vote; approval needs unanimity of the remaining eligible members. A malicious majority also cannot block forever: once two adjudicators establish compromise, the accused are excluded and the honest remainder decides.

Tested combinations (§4): K2+K3 and K2+K3+K5 owner sets open and complete a guardian replacement; K1+K2 (one role) cannot; `tests/v4/r3-governance.test.mjs` and `contract-v4/src/tests.rs::v4_guardian_emergency_replacement_two_of_three_with_k2_k3_and_k2_k3_k5`.

## 3. Ballot confidentiality (§5, INV-V4-04)

Commitment `SHA-256(domain ‖ canon{gcaseDigest, voterId, choice, salt})`; sealed payload X25519 (ephemeral) → HKDF-SHA-256 → AES-256-GCM with AAD `gcaseDigest|voterId`; voter signature over `{gcaseDigest, voterId, commitment, sealedDigest}`.

What this provides: individual dissent is hidden from the Root, the chain, other voters and the AI; only the tally service can read choices. What it does **not** provide: anonymity (voters are identified), protection against a malicious tally service leaking choices, or privacy of an APPROVED result (unanimity reveals every choice). With a single eligible voter any result reveals that vote. The contract keeps only commitments on-chain; sealing is off-chain.

## 4. On-chain mirror

`contract-v4` implements the R-1 rules (ORC intent bound to operation, case digest, time window, key and single-use nonce; expiry; cooldown; claim budget; burned keys; ORC-attested open) and the COMPROMISE-by-adjudicator governance path with on-chain commitments and openings. UNAVAILABLE / WITHDRAWAL grounds and sealed-ballot encryption exist only in the JS Root. Level: **local contract verified** (`cargo test`, wasm build); **Testnet verified: NO**.
