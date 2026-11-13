# SafeBox V4 security evaluation

Branch `feature/v4-intent-bound-recovery` (Draft PR #6, never merge), base V3 `feature/v3-purpose-recovery` (`6d71cd0`).

| Candidate | Commit | What it is |
|---|---|---|
| A (original) | `33ea4f8` (A_r1, B_r3), `802ab9c` (A2, B2, C, D, E: tests, docs and one extra scenario only, no security-code change) | first complete V4 |
| B (repaired, frozen) | `780e676` | A + F-V4-01 + F-V4-02 |
| harness update | `483594c` | campaign owner uses an ORC-attested open after an attacker-caused cooldown (no security-code change) |
| C (review fix) | `69d5f08` | B + per-hold freeze provenance and consent-screen disclosure (F-V4-01b, owner review of `780e676`) |
| D (repaired, frozen) | `705fdbb` | C + F-V4-03 (ORC-attested owner quorum may include a suspended owner key); campaign owner simulator drives R-3 |

## 1. Verification levels (§17), kept separate

| Category | Status | Evidence |
|---|---|---|
| Implemented | V4 Root, intent / challenge / summary, ORC, R-1 rules, R-3 governance, sealed ballots, verifier, red-team harness, contract-v4 | `src/v4/`, `contract-v4/` |
| Deterministic mock verified | yes: all JS suites, recovery matrix, mutations, UI-manipulation tests | below |
| Software-authenticator verified | yes: WebAuthn passkeys via the V3 soft authenticator (origin, rpId, challenge = intent digest, UV, counters) | `tests/v4/intent-ui.test.mjs` |
| Hardware trusted-UI verified | **no**: trusted display and protected confirmation are simulated | TRUSTED-CONFIRMATION.md |
| OS-isolated end-to-end verified | **no**: the OS privilege matrix is verified (8 principals, 360 checks, 0 violations); the V4 protocol was not run across them | `docs/evidence/v4/os/os-matrix.json` |
| Local contract verified | yes: `contract-v4` 34 Rust tests, wasm build (650,323 bytes) | `cargo test --manifest-path contract-v4/Cargo.toml` |
| Testnet verified | **no** (NEAR RPC blocked here; no funded accounts) | |
| Not implemented | on-chain SUSPEND / UNAVAILABLE / WITHDRAWAL grounds / ballot sealing; ZK tally; hardware attestation | RESIDUAL-RISKS.md |
| Blocked | Testnet deployment; hardware trusted UI | |

## 2. Test totals (candidate D, `705fdbb`; B `780e676` had JS 299/299 and 22/22 mutations, C `69d5f08` 302/302 and 26/26)

| Suite | Result | Command |
|---|---|---|
| All JS (V1, V2, V2-B, V3, V4) | **304 / 304 pass** (V1–V3: 208, unchanged from V3; V4: 96) | `npm test` (as root for the OS tests) |
| V4 JS | 96 / 96 | `npm run v4:test` |
| Rust contract (V1) | 5 / 5 | `npm run test:contract` |
| Rust contract-v3 | 24 / 24 | `npm run test:contract-v3` |
| Rust contract-v4 | 34 / 34 | `npm run test:contract-v4` |
| Mutation testing | **28 / 28 caught** (first run on A: 15 / 19, then 4 targeted tests; F-V4-01 adds 3, F-V4-01b 4 and F-V4-03 2 mutations) | `npm run v4:mutations`; `docs/evidence/v4/mutations.json`, `mutations-run1.json` |
| Recovery matrix | 32 / 32 subsets as expected, 11 named scenarios; regenerated on B, C and D unchanged | `npm run v4:matrix`; `docs/evidence/v4/recovery-matrix.{json,md}` |
| OS privilege matrix | 360 checks, 0 violations | `sudo npm run v4:os` |

## 3. R-1 closure (acceptance 1, 4)

- Baseline: the V3 R-1 takeover reproduces on unchanged V3 code (`tests/v4/r1-closure.test.mjs` BASELINE).
- V4: the same collusion (stolen K1 + all guardians + both IDVs + channel acks + 73 h silence) ends with `OWNER_AUTHORIZATION_REQUIRED`; the case expires (`EXPIRED_UNAPPROVED`), the lockdown is released, there is no authority change, and the verifier reports 0 takeovers.
- Matrix Q2: the maximal R-1 collusion is denied for every one of the 32 loss subsets.
- Stolen K1 + its APC key cannot produce an ORC authorization (`ORC_UNKNOWN_OR_INACTIVE`, `OWNER_AUTHORIZATION_ONE_ORC`); a self-made key labelled `orc-1` is refused.
- Cooldown is keyed on the subject; changing the case ID does not help; plan keys are burned; claim and lockdown budgets hold (146 h worst case, see R-V4-06).

## 4. R-3 closure (acceptance 2, 3)

- Owner sets K2+K3 and K2+K3+K5 complete an emergency guardian replacement; K1+K2 (one role) cannot.
- Two of three and three of three colluding guardians, both IDVs compromised, combined attacks, forged accusations, false evidence, excluded-member double counting, quorum manipulation, removal without replacement and malicious replacement credentials: `tests/v4/r3-governance.test.mjs` (16 tests).
- Matrix scenarios: compromised guardians replaced, then the owner recovers (NEW_EPOCH); compromised IDVs replaced, then the owner recovers; a false accusation with one bribed adjudicator is refused (`ACCUSATION_NOT_ESTABLISHED`).
- No payment, Purpose, budget or unfreeze authority in the governance path (INV-V4-09).

## 5. Intent, challenges, confirmation (acceptance 5, 6, 7)

See AUTHORIZATION-INTENT.md and TRUSTED-CONFIRMATION.md. Every intent field is bound (`INTENT_MISMATCH` for each, with a full quorum and a fresh grant). Grants are 256-bit, ≤ 120 s, action- and credential-bound and single use; consumption is atomic and survives a restart. Two software-only passkeys cannot approve a CRITICAL action. UV is checked but never treated as a biometric; the General Zone cannot produce a UV assertion without the authenticator.

## 6. Red team: Opus 4.8 campaigns (§13)

Model: requested `claude-opus-4-8` for every call, no fallback configured; every call was served by `claude-opus-4-8`; **0 safety stops; 0 usage-limit stops; 0 incomplete campaigns.** The attacker runs in the General Zone tool surface only. Evidence: `docs/evidence/v4/redteam/<runId>/` (summary, trajectory, transcript, actuator log, root chain, system prompt). Reproduce: `npm run v4:redteam -- --scenario <S> --model claude-opus-4-8 --turns 10 --rounds 2 --budget 3 --label <L>`.

### 6.1 Original candidate (label `A-original`)

| Scenario | Group | Calls | Output tokens | Cost $ | Unauth. financial | Unauth. authority | Takeovers | Purpose viol. | Result |
|---|---|---|---|---|---|---|---|---|---|
| A_r1 | A (R-1) | 20 | 29,771 | 1.57 | 0 | 0 | 0 | 0 | 2 in-Purpose payments with stolen K1 (R-V4-01) |
| A2_r1case | A (R-1, case focus) | 20 | 35,430 | 1.78 | 0 | 0 | 0 | 0 | attacker case opened; no reconstitution |
| B_r3 | B (R-3) | 20 | 37,594 | 2.03 | 0 | 0 | 0 | 0 | **F-V4-01: FREEZE + SUSPEND k3, k5 with stolen k1+k2 => permanent owner lockout** |
| B2_r3quorum | B (R-3, quorum) | 20 | 38,193 | 2.17 | 0 | **1** | 0 | 0 | governance case OPEN with DAILY+RECOVERY + 2 bribed adjudicators; ORC-cancelled after 1 h; nobody replaced (R-V4-04) |
| C_ui | C (UI) | 20 | 58,293 | 2.69 | 0 | 0 | 0 | 0 | owner approved 2 exact requests, declined 3 mismatching ones |
| D_fin | D (financial) | 20 | 27,299 | 1.38 | 0 | 0 | 0 | 0 | owner recovered (72 h); 83/83 legitimate payments |
| E_avail | E (availability) | 20 | 26,723 | 1.39 | 0 | 0 | 0 | 0 | **F-V4-01 again: the stolen FREEZE key suspended all four other keys** |
| **Total** | | **140** | **253,303** | **13.02** | **0** | **1** | **0** | **0** | |

### 6.2 Repaired candidate `780e676` (label `B-fresh`)

| Scenario | Calls | Output tokens | Cost $ | Unauth. financial | Unauth. authority | Takeovers | Purpose viol. | Permanent lockout | Legit payments |
|---|---|---|---|---|---|---|---|---|---|
| B_r3 | 20 | 47,934 | 2.51 | 0 | 0 | 0 | 0 | no | 0/0 (both DAILY keys stolen; owner did not discover) |
| E_avail | 19 | 23,373 | 1.18 | 0 | 0 | 0 | 0 | no | 31/31 |
| A2_r1case | 20 | 18,437 | 1.01 | 0 | 0 | 0 | 0 | no | 82/82 |
| B2_r3quorum | 20 | 57,443 | 2.91 | 0 | 0 | 0 | 0 | no | 31/31 |
| C_ui | 20 | 42,367 | 2.11 | 0 | 0 | 0 | 0 | no | 31/31; 4 exact owner approvals, 0 swaps |
| D_fin | 20 | 28,509 | 1.41 | 0 | 0 | 0 | 0 | no | 83/83; owner recovered (72 h) |
| A_r1 | 20 | 27,884 | 1.40 | 0 | 0 | 0 | 0 | no | 94/94; 2 in-Purpose attacker payments (R-V4-01) |
| **Total** | **139** | **245,947** | **12.53** | **0** | **0** | **0** | **0** | | |

In the fresh E_avail the attacker opened a false claim that the owner ORC-cancelled; that started the 12 h subject cooldown, and the campaign owner simulator kept retrying a plain open (`RECOVERY_REATTEMPT_COOLDOWN` ×7). This is a harness gap (the protocol offers an ORC-attested open exactly for this) and a reported residual (R-V4-11). Harness fix `483594c`; rerun in §6.3.

### 6.3 Harness rerun

`E_avail` on `483594c` (label `B-fresh-h2`): 20 calls, all `claude-opus-4-8`, 24,391 output tokens, $1.23, 0 safety stops. 0 unauthorized financial / authority effects, 0 takeovers, no lockout, 31/31 legitimate payments. The attacker opened one false claim (`rc-001`), the owner ORC-cancelled it after 1 h, and the attacker did not suspend owner keys this time, so the ORC-attested reopen was not exercised by the model. That path is covered deterministically by the matrix scenario "identity dispute" and `legitimateRecoveryV4`.

### 6.4 Review-fix candidate `69d5f08` (label `C-fresh`)

| Scenario | Calls | Output tokens | Cost $ | Unauth. financial | Unauth. authority | Takeovers | Permanent lockout | Legit payments |
|---|---|---|---|---|---|---|---|---|
| B_r3 | 20 | 27,019 | 1.54 | 0 | 0 | 0 | **yes (F-V4-03)** | 0/0 (both DAILY keys stolen) |
| E_avail | 20 | 23,732 | 1.24 | 0 | 0 | 0 | no | 31/31; 6 attacker freezes unfrozen by the owner |
| **Total** | **40** | **50,751** | **2.78** | **0** | **0** | **0** | | |

In B_r3 the attacker (stolen k1 + k2, colluding guardians g1 + g2) froze the vault and suspended k3 and k5. The owner noticed and opened a minority recovery with the suspended survivors (F-V4-01 lets their own consent count), but g1 and g2 refused, so the case could not reach the guardian quorum (`GUARDIAN_QUORUM_NOT_MET`). The R-3 route that replaces colluding guardians needs two owner roles, and the owner's only roles outside the attacker's hands were the suspended k3 / k5 and the ORC; suspended credentials did not count (`APPROVAL_CREDENTIAL_NOT_ACTIVE`). Result: permanent lockout. This is F-V4-03 (§7).

### 6.5 Candidate `705fdbb` (label `D-fresh`)

| Scenario | Calls | Output tokens | Cost $ | Unauth. financial | Unauth. authority | Takeovers | Permanent lockout | Legit payments |
|---|---|---|---|---|---|---|---|---|
| B_r3 (`--turn-hours 12`) | 20 | 31,273 | 1.64 | 0 | 0 | 0 | no | 2/2 after recovery |
| E_avail | 20 | 33,765 | 1.67 | 0 | 0 | 0 | no | 31/31 |
| **Total** | **40** | **65,038** | **3.31** | **0** | **0** | **0** | | |

B_r3 replays the F-V4-03 shape with a fresh attacker: with stolen k1 + k2 it froze the vault and suspended k3 (its k5 suspension was refused as malformed), tried to open a governance case against the honest guardian g3 (refused; the owner also declined one "routine guardian hygiene" request on its device), and opened no successful case. The owner discovered the loss, suspended k1 + k2, and opened a recovery that g1 + g2 refused (`GUARDIAN_QUORUM_NOT_MET` ×7). After 6 h the owner ORC-cancelled it and opened R-3 with **ORC + the suspended k3** against g1 + g2 (MISCONDUCT, adjudicators adj-2 + adj-3); 3/3 eligible ballots approved, the case executed after the 24 h delay, and the reopened recovery completed 72 h later: RECOVERED, freeze lifted, epoch 3, 0 unauthorized authority changes (the two guardian removals are the owner's). Total owner time from discovery to recovery: about 104 h.

E_avail: the attacker (stolen k4 FREEZE key) opened one false claim, which the owner ORC-cancelled after 1 h; 11 freeze attempts were refused at the source check (`FREEZE_SOURCE`); 0 lockdown hours; 31/31 legitimate payments.

**All campaigns: 379 model calls (A 140, B 139 + 20, C 40, D 40), $32.87, every call served by `claude-opus-4-8`, 0 safety stops, 0 usage-limit stops.**

## 7. Hardening loop (§14)

### F-V4-01: suspension lockout (availability, protocol bug inherited from V3)

1. **Evidence preserved**: `docs/evidence/v4/redteam/2026-11-13T1912-B_r3-A-original/` and `2026-11-13T1958-E_avail-A-original/` (unchanged).
2. **Reproduced independently**: `tests/v4/f01-suspension-lockout.test.mjs` BASELINE (V3 code) and the V4 pre-fix replay (owner recovery `FAILED:QUORUM_NOT_SATISFIED` at `consent k3-root-hw`).
3. **Invariant violated**: INV-V4-10 (legitimate recovery preservation). SUSPEND is a one-signature protective action, so one stolen key can suspend all others. V3 allows a suspended survivor to consent (`allowSuspendedSelf`), but its quorum counting excludes the subject, so that consent never counted.
4. **Classification**: implementation bug (V3 `verifyApprovals` subject exclusion applied to self-consent), plus a protocol gap (an attacker's protective actions outlive the attacker's revoked key).
5. **Narrow fix** (`src/v4/root/chain.mjs`): (a) a suspended survivor's own single-signer consent counts, verified as an AuthorizationIntent with UV and a one-time challenge (a V3 action-digest consent is refused); (b) SUSPEND and owner-source FREEZE record their approvers; a completed recovery (RECOVERY_COMPLETE / RECONSTITUTE) lifts the suspensions and the freeze imposed **only** by credentials it revokes. Owner-imposed suspensions and supervisor breach freezes stay.
6. **Exact replay**: the campaign B shape (stolen k1+k2: FREEZE, SUSPEND k3/k4/k5) and the campaign E shape (stolen k4 suspends all four) now end with RECOVERED, all owner keys active and the freeze lifted, with 0 unauthorized authority changes.
7. **Mutations**: 3 new mutations (consent not counted, lift removed, over-broad lift) are all caught.
8. **Legitimate-owner tests**: recovery matrix unchanged (32/32); narrowness test: owner-imposed suspension kept, attacker case still cannot complete.
9. **Regressions**: V1–V3 208/208, Rust 5 + 24 + 34.
10. **Frozen**: `780e676`.
11. **Fresh campaign**: §6.2: no permanent lockout in any scenario.

The repair is not FREEZE-based: no denial in the replay relies on a global freeze.

### F-V4-01b: freeze-reinforcement provenance (owner code review of `780e676`)

1. **Observation** (review, not an executed exploit): V3 treats a FREEZE on an already frozen vault as a reinforcement without recording the signer; the `780e676` repair recorded only the first freeze's signers and lifted the whole freeze when those were all revoked.
2. **Reproduced**: on `780e676`, stolen K1 freezes, the owner deliberately reinforces with K2, a recovery revokes K1, and the vault is unfrozen. The K2 intent is lost (`tests/v4/f01-suspension-lockout.test.mjs` REINFORCEMENT fails on `780e676`, passes on C).
3. **Invariant**: owner intent preservation (INV-V4-05 / INV-V4-10 side: an automatic cleanup must not undo a deliberate owner action).
4. **Fix**: every FREEZE (including a reinforcement) is its own hold with provenance (`s.v4.freezeHolds`: approvers, or `source:supervisor`). A completed recovery drops only the holds placed solely by keys it revokes. The freeze lifts only if no other hold remains, it is an owner-source freeze, and it is not a supervisor breach freeze (that one lifts only with its trusted repair certificate). The consent / ORC screen lists every suspension it would reactivate and every freeze hold it would drop, and whether the freeze stays, so the owner approves those effects explicitly (bound through `summaryDigest`).
5. **Tests**: REINFORCEMENT (vault stays frozen; the owner unfreezes with K2 + K3); SUPERVISOR (both orders: the breach freeze stays and requires repair); HONEST OWNER FREEZE (a freeze placed with a key that is later rotated stays; one placed with a key later lost is shown, a declining owner keeps it, an approving owner can re-freeze with one tap).
6. **Mutations**: 4 new (reinforcement not recorded, lift despite another hold, supervisor freeze lifted, disclosure removed), all caught (the supervisor one only by a defence-in-depth test, since the supervisor's own hold already keeps the freeze).
7. **Regressions**: JS 302/302; recovery matrix unchanged; contract code unchanged.
8. **Frozen**: `69d5f08`; fresh campaigns in §6.4.

### F-V4-03: suspension plus guardian collusion blocks both recovery and R-3 (found by C-fresh B_r3)

1. **Evidence preserved**: `docs/evidence/v4/redteam/2026-11-13T2128-B_r3-C-fresh/` (unchanged).
2. **Reproduced**: `tests/v4/f01-suspension-lockout.test.mjs` F-V4-03 DEADLOCK: with stolen k1 + k2, k3 and k5 suspended and g1 + g2 refusing, the recovery cannot complete and a governance open with ORC + k3 gives `APPROVAL_CREDENTIAL_NOT_ACTIVE` on `69d5f08`.
3. **Invariant violated**: INV-V4-10 (legitimate recovery preservation), and INV-V4-03's promise that a malicious guardian majority cannot block forever.
4. **Classification**: protocol gap. F-V4-01 restored the suspended survivors' voice in recovery cases but not in governance cases, and the only exit from a colluding guardian majority is governance.
5. **Narrow fix** (`verifyOwnerQuorum`, `src/v4/root/chain.mjs`): in an owner quorum that includes an active ORC approval, a **suspended** (never revoked or provisional) owner credential counts as one owner role. Without the ORC a suspended credential still does not count. The ORC is offline and independent of the stealable devices (trust assumption 1), so this cannot be triggered by the thief alone.
6. **Exact replay**: same shape, now ORC + suspended k3 open `GUARDIAN_EMERGENCY_REPLACE` against g1 + g2 (MISCONDUCT, two honest adjudicators), the honest electorate approves unanimously, the 24 h delay passes, the case executes, and the owner's new recovery completes: RECOVERED, all owner keys active, no freeze, 0 unauthorized authority changes.
7. **Assumption (stated, not proven)**: two independent adjudicators find a documented refusal to confirm a genuine owner recovery to be misconduct. If no two adjudicators agree, the lockout remains (residual R-V4-14).
8. **Mutations**: 2 new (suspended owner keys never count; suspended owner keys count even without the ORC).
9. **Regressions**: JS 304/304; recovery matrix unchanged; contract code unchanged (the contract has no SUSPEND).
10. **Harness**: the campaign owner simulator now ORC-cancels its own stuck case after 6 h of `GUARDIAN_QUORUM_NOT_MET`, opens R-3 against the refusing guardians, ballots for the honest electorate, executes after the delay and reopens the recovery.
11. **Frozen**: `705fdbb`; fresh campaigns in §6.5.

### F-V4-02: withdrawal statements were standing resignations (found in self-review)

A WITHDRAWAL ground statement was signed over `{account, chain, subject, key}` only, so a statement signed once could be reused in any later governance case. Now it is bound to `gcaseId` (`src/v4/root/chain.mjs`, `src/v4/kit.mjs`); test in `tests/v4/r3-governance.test.mjs` (a withdrawal for another case gives `WITHDRAWAL_SIGNATURE`).

## 8. Usability (§15)

From `docs/evidence/v4/recovery-matrix.md` (gestures = physical confirmations including channel acknowledgements; prompts = trusted-path prompts; signatures counted separately):

| Loss | Outcome | Gestures / prompts | Independent signer interactions | Chain signatures | Latency |
|---|---|---|---|---|---|
| 1–2 keys (15 subsets) | RECOVERED | 8 / 5 | 3 | 10–11 | 1.02 h |
| 3–4 keys (15 subsets) | NEW_EPOCH | 10–11 / 7–8 | 5 | 11–12 | 72.02 h |
| 5 keys | RECOVERY_IMPOSSIBLE | 5 / 5 | 1 | 2 | 72 h |

- Legitimate recovery completion: 30 / 30 supported subsets; 0 false denials in the matrix; 0 owner cancellations.
- Legitimate payment settlement in campaigns: 100% wherever the owner still held a DAILY key (A 31/31, B2 31/31, C 31/31, D 83/83, E 27/27 and 31/31, A2 79/79 and 82/82, A fresh 94/94).
- Owner prompts in C_ui: 10 (original) and 12 (fresh) for 2 owner tasks; flood-guard hits 0.

## 9. Invariants (§16)

| Invariant | Status | Main evidence |
|---|---|---|
| INV-V4-01 No silence authorization | holds (deterministic mock) | r1-closure, matrix Q2, campaigns A, A2 |
| INV-V4-02 Independent owner intent | holds | r1-closure, mutation-kills ORC DIGEST BINDING |
| INV-V4-03 No circular guardian authority | holds; see R-V4-04 for the exceeded-assumption case | r3-governance, B, B2 |
| INV-V4-04 Private consent | holds to the stated level (confidentiality via tally, not anonymity) | ballot-integration |
| INV-V4-05 Display / execution consistency | holds for the simulated trusted path | intent-ui, mutation-kills |
| INV-V4-06 Single-purpose authorization | holds | intent-ui APPROVE A EXECUTE B |
| INV-V4-07 Time and replay safety | holds | intent-ui CHALLENGES / CONCURRENCY, mutation-kills |
| INV-V4-08 No biometric export | holds by construction (only signatures + UV bit) | intent-ui WEBAUTHN |
| INV-V4-09 Purpose and asset preservation | holds: 0 unauthorized financial effects, 0 Purpose violations in 379 calls | campaigns, V3 suites |
| INV-V4-10 Legitimate recovery preservation | **violated on A (F-V4-01) and on C (F-V4-03, guardian collusion), holds on D under the adjudicator assumption (R-V4-14)** | f01-suspension-lockout, fresh campaigns |
