# SafeBox V4 security evaluation

Branch `feature/v4-intent-bound-recovery` (Draft PR #6, never merge), base V3 `feature/v3-purpose-recovery` (`6d71cd0`).

| Candidate | Commit | What it is |
|---|---|---|
| A (original) | `33ea4f8` (A_r1, B_r3), `802ab9c` (A2, B2, C, D, E: tests, docs and one extra scenario only, no security-code change) | first complete V4 |
| B (repaired, frozen) | `780e676` | A + F-V4-01 + F-V4-02 |
| harness update | `483594c` | campaign owner uses an ORC-attested open after an attacker-caused cooldown (no security-code change) |

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

## 2. Test totals (candidate B, `780e676`)

| Suite | Result | Command |
|---|---|---|
| All JS (V1, V2, V2-B, V3, V4) | **299 / 299 pass** (V1–V3: 208, unchanged from V3; V4: 91) | `npm test` (as root for the OS tests) |
| V4 JS | 91 / 91 | `npm run v4:test` |
| Rust contract (V1) | 5 / 5 | `npm run test:contract` |
| Rust contract-v3 | 24 / 24 | `npm run test:contract-v3` |
| Rust contract-v4 | 34 / 34 | `npm run test:contract-v4` |
| Mutation testing | **22 / 22 caught** (first run on A: 15 / 19, then 4 targeted tests; F-V4-01 adds 3 mutations) | `npm run v4:mutations`; `docs/evidence/v4/mutations.json`, `mutations-run1.json` |
| Recovery matrix | 32 / 32 subsets as expected, 11 named scenarios; regenerated on B unchanged | `npm run v4:matrix`; `docs/evidence/v4/recovery-matrix.{json,md}` |
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

**All campaigns: 299 model calls, $26.78, every call served by `claude-opus-4-8`, 0 safety stops, 0 usage-limit stops.**

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
| INV-V4-09 Purpose and asset preservation | holds: 0 unauthorized financial effects, 0 Purpose violations in 299 calls | campaigns, V3 suites |
| INV-V4-10 Legitimate recovery preservation | **violated on candidate A (F-V4-01), holds on B** | f01-suspension-lockout, fresh campaigns |
