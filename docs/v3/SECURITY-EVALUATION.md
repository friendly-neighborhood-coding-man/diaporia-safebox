# SafeBox V3 security evaluation

Branch `feature/v3-purpose-recovery` (Draft PR #5, never merge).

- Candidate A = `db316d0`, the original.
- Candidate B = `06a37b4`, after F-V3-02 and the harness fix.

Every number below comes from files under `docs/evidence/v3/`. None of it touches Mainnet or real funds, and no
Testnet transaction was made.

## 1. Summary

| | Result |
|---|---|
| Unauthorized financial effects (deterministic suites + 6 LLM runs) | **0** |
| Unauthorized authority changes / takeovers outside the documented residual R-1 | **0** |
| Findings | **F-V3-01** (guardian collusion + 1 stolen key → takeover, found in development), **F-V3-02** (recovery veto by 1 stolen channel / 1 guardian, found by LLM campaign A). Both repaired, replayed and mutation-tested |
| Residuals | R-1 (takeover needs all guardians + both IDVs + a majority of the owner's channels + owner silent 72 h), R-2/R-3 (availability, assets preserved) |
| Tests at candidate B + this doc | JS **208/208** (V3: 91), Rust `contract-v3` **24/24**, OS matrix **145 checks / 0 violations** |
| LLM attacker | **Claude Opus 4.8 only.** 113 calls, 113 served by `claude-opus-4-8`, 0 substitutions, 0 safety stops, 0 usage-limit stops. Estimated cost **$8.26** |

## 2. Deterministic attack suites (candidate B)

| Suite | Tests | Covers |
|---|---|---|
| `root-lifecycle` | 7 | pay roles, UV, exact binding, amendment quorum, immutable fields, rotation, freeze/unfreeze, supervisor freeze + repair cert, revoke/refill |
| `authority-attacks` | 14 | WebAuthn forgery/replay/clone, ed25519 replay and moved signatures, credential independence, genesis swap, matrix floors, multi-admin distinct holders, deceased-admin evidence review, concurrent rotation, restart, crash after persist, rollback/fork/tamper, General Zone root access, resource exhaustion, executor ≠ credential |
| `recovery-attacks` | 15 | fake claims, conflicting claims, plan independence, channel forgery, thief objection, **guardian collusion (F-V3-01)**, guardian/IDV impersonation, 72 h boundary, early completion, freeze of governance during a case, old-epoch reuse, denominator laundering, K4/K5/guardians never pay, **R-1 residual** |
| `recovery-combinations` | 2 (32-case sweep) | every subset of K1..K5 lost |
| `f-v3-02-recovery-veto` | 10 | 4 exact replays + 6 mutations |
| `owner-governance-route` | 1 | owner refills DAILY/FREEZE without third parties when guardians and IDVs collude |
| `redteam-actuator` | 1 | harness: attacker key/action references |
| `webauthn` | 3 | RP registration/assertion, CBOR strictness |
| `deployment` | 4 | D1–D4 deployment invariants + OS privilege matrix |
| `contract-v3` (Rust) | 24 | payments, signatures, replay, limits, freeze/K4, amendment, revoke/rotate, epoch staleness, recovery claim/consent/guardian/identity/window/dispute, lockdown and reconstitution, laundering, F-V3-02 port |

**Mutation checks.**
- **Contract:** each of these was removed in turn, and each removal was caught:
  - the dispute check;
  - the unfreeze quorum;
  - the baseline denominator;
  - the self-revoke check.
- **F-V3-02:** 6 mutation tests. They cover a missing survivor consent, a below-quorum override, guardian objections
  not outnumbered, a survivor objection, reconstitution strictness, and double counting.
- **F-V3-01:** see its TAP files.

## 3. Findings

### F-V3-01: guardian collusion + one stolen key overrides the owner (found in development)

- **Attack.** The attacker has K1, all three guardians and both identity verifiers. They claim K2..K5 are lost, which
  is more than 50% and so goes to reconstitution, and consent with K1. The real owner objects with K2 and K3, and the
  attacker overrides those objections.
- **Original result:** NEW_EPOCH. Takeover. Evidence: `findings/F-V3-01-guardian-collusion-override-ORIGINAL.tap`.
- **Repair.**
  - Claimed-lost-key objections are not overridable on the reconstitution path.
  - On the recovery path they are overridable only when survivors strictly outnumber them.
  - Reconstitution needs NO_OBJECTION acks from a majority of the subject holder's channels.
- **Post-repair:** `F-V3-01-POST-REPAIR-replay-and-mutations.tap`, 6/6.
- **Residual R-1** is kept as a passing test that documents it.

### F-V3-02: one stolen channel or one bad guardian vetoes recovery forever (found by LLM campaign A)

- **Found by:** `redteam/2026-11-13T1646-thief-A-original`, Opus 4.8. The attacker held stolen K1, `ch-phone` and `g1`.
  In turn 8 it submitted a channel OBJECTION ack against the owner's case. The owner's override then failed with
  `OVERRIDE_NEEDS_RECON_GUARDIAN_QUORUM`, because only 2 honest guardians were left and 3 were required.
- **Impact.** The case stayed on HOLD forever. For a lost ROOT or RECOVERY key there is no other refill route, so the
  owner would lose governance permanently. No funds moved: 111 of 111 owner payments settled.
- **Original:** `findings/F-V3-02-recovery-veto-ORIGINAL.tap`, 6 failing.
- **Repair** (`7655427`). On the recovery path the following become overridable with all survivor consents, the normal
  guardian quorum and identity:
  - channel objections;
  - claimed-lost-key objections;
  - minority-guardian objections.
  Guardian approvals must strictly outnumber guardian objections, and an objector is not counted as approving. The
  reconstitution path and surviving-key objections are unchanged. The repair is ported on-chain as
  `recovery_override`.
- **Post-repair:** `findings/F-V3-02-POST-REPAIR-replay-and-mutations.tap`, 10/10.
- **Fresh confirmation:** in `redteam/2026-11-13T1711-thief-B-fresh` the attacker again put the case on HOLD. The owner
  overrode it and **recovered at 72 h**.

### Harness defect (not a security finding)

- In `insider-A-original` the attacker could not open a recovery case: `ENROLLMENTS_INVALID`, with empty-action turns.
- Cause: enrollment blobs were clipped in observations, and they were bound to an earlier action nonce.
- Fix (`e680452`): `build_action` accepts `nonce`, `planOwnCredIds` and `newCredentialOwnCredId`. `submit_root`
  accepts `actionDigest`.
- Result: in `insider-B-fresh` the attacker opened a case. It was blocked by the owner's objection and by
  `OVERRIDE_NEEDS_ALL_SURVIVOR_CONSENTS`.

### Owner-procedure observation (utility, not a protocol finding)

- In `thief2` (stolen K1+K4, all guardians and both IDVs colluding) the owner's recovery case never completes, in both
  campaigns. That is by design (R-3): every honest identity and guardian source is gone.
- The protocol still lets the owner cancel the case and refill the DAILY and FREEZE vacancies with K2+K3
  (`tests/v3/owner-governance-route.test.mjs`).
- The campaign's owner simulator does not take that route, so `ownerRecovery = NOT_FINISHED` in those runs measures the
  simulator, not the protocol.

## 4. LLM red-team campaigns

**Setup**
- Attacker: Claude CLI brain with **no tools**, a scrubbed environment and a public-information-only system prompt.
  It acts only through the General-Zone actuator.
- Compromise is per scenario. The attacker never gets owner secrets it wasn't given, never gets the evaluator, and
  never gets host tools.
- 10 turns × 2 rounds; 3 h of virtual time per turn; the owner pays hourly; up to 80 h of drain afterwards.
- Model guard: the run stops on any served model ≠ requested, on the usage limit, or on a safety fallback.
- There is no Sonnet fallback (Eric's instruction).

| Run | Candidate (src) | Calls (served Opus 4.8) | Cost | Unauth. fin. | Unauth. auth. | Takeover | Owner payments settled | Owner recovery |
|---|---|---|---|---|---|---|---|---|
| thief-A-original | db316d0 | 20 / 20 | $1.87 | 0 | 0 | 0 | 111/111 | NOT_FINISHED (**F-V3-02**) |
| insider-A-original | 68714a5 (src identical to db316d0) | 15 / 15 | $1.05 | 0 | 0 | 0 | 31/31 | n/a (no owner loss) |
| thief2-A-original | db316d0 | 19 / 19 | $1.72 | 0 | 0 | 0 | 111/111 | NOT_FINISHED (R-3; see §3) |
| thief-B-fresh | 06a37b4 | 20 / 20 | $1.02 | 0 | 0 | 0 | 80/80 | **RECOVERED at 72 h** |
| insider-B-fresh | 06a37b4 | 20 / 20 | $1.53 | 0 | 0 | 0 | 31/31 | n/a |
| thief2-B-fresh | 06a37b4 | 19 / 19 | $1.07 | 0 | 0 | 0 | 111/111 | NOT_FINISHED (R-3) |
| **Total** | | **113 / 113** | **$8.26** | **0** | **0** | **0** | **475/475** | |

Notes on the table:
- Costs are the CLI's reported estimates.
- Per-call served models, token usage and cost are in each run's `summary.json` (`perCallModels`).
- Model IDs appear only in this evidence and in chat. They are never in commits.

**Attacker tactics observed:**
- payment redirection to attacker accounts (self-signed and stolen-K1 PAYCAPs to `attacker.mock`);
- capability reuse;
- objection/HOLD lockout through stolen channels and guardians;
- opening reconstitution cases with its own key plans;
- forged identity and guardian evidence;
- override and withdraw probing;
- consent forgery with its own keys.

All of these were denied at the vault (purpose recipient, exact binding, epoch) or at the Root (signature, survivor
consent, quorum).

**Success rates:**
- attacker theft: 0/6 runs;
- attacker authority change: 0/6;
- attacker permanent lockout of the owner: 1/3 on candidate A (F-V3-02) and 0/3 on candidate B, with thief2 excluded
  as R-3;
- owner payment success: 475/475;
- owner recovery when the protocol permits it: 1/1 on candidate B.

## 5. Utility

- **Loss sweep (32 cases):**
  - 1–2 lost: RECOVERED in 1.02 h with all channels acked;
  - 3–4 lost: NEW_EPOCH in 72.02 h;
  - 5 lost: RECOVERY_IMPOSSIBLE, reported as such;
  - payment works after every successful case (30/30).
- **Owner steps:** 10–11 signed owner actions per recovery.
- **Normal payments:** buffered by `bufferMs`, with no extra owner step compared with V2-B.
- **Development-time usability finding:** UV is required only for multi-signer rules, so hardware ed25519 recovery
  keys can consent.

## 6. Not verified / not implemented

- **Real Testnet / Mainnet:** not done. NEAR RPC is unreachable from the cloud, there are no funded accounts, and no
  authorization was given.
- **Live OS-isolated V3 services:** not built. The V3 services run in-process in tests. Only the five-principal
  privilege matrix is OS-verified. The V2 OS-isolated deployment and its tests are unchanged and still pass.
- **Physical authenticators:** not tested. A software WebAuthn authenticator was used, and no attestation trust store
  is implemented.
- **Real identity verifiers, registrars and notification providers:** simulated as pinned Ed25519 signers.
- **Guardian-set rotation:** not implemented as its own governance action.
- **Multi-admin on-chain:** not implemented. The contract hard-codes the personal matrix.
- **Owner simulator:** does not use the governance refill route (§3).
- **Candidate tags:** `v3-candidate-A` and `v3-candidate-B` exist locally only, because the proxy refuses tag pushes.
  Their commits are on the branch.
