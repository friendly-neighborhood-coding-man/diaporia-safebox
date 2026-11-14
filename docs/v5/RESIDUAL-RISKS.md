# SafeBox V5 residual risks and unverified boundaries

Everything here is reported on purpose. V4 residuals (`docs/v4/RESIDUAL-RISKS.md`, R-V4-01..14) still apply unless a
row below says V5 changed them.

## A. Residuals by design or accepted

| ID | Residual | Why it remains | Mitigation in V5 | Evidence |
|---|---|---|---|---|
| R-V5-01 | **A stolen PAY key still settles in-Purpose payments before detection.** A slow drain below the thresholds is never delayed. | The engine sees behaviour, not intent. Thresholds that catch slow drains would delay normal owners (no weakening to reduce FP, no tightening that breaks legitimate use without evidence). | Cold-start priors and absolute ceilings; the 10-minute buffer means the first delay also catches payments that were already buffered; the owner is e-mailed at the first delay. | Datasets: 0 settled before detection for the fast personas, but 24 (seed 1) and 98 (seeds 2–5) settled across the slow-drain and just-under-threshold personas. Red team: 0–2 attacker payments of 0.06 NEAR settled before the first delay per campaign. |
| R-V5-02 | **A stolen PAY key can grant a delegation within the Purpose** (DELEGATION_GRANT needs one PAY credential through a trusted path; a stolen phone with its PIN passes protected confirmation). | The owner's own phone is the delegation authority. | The delegation is a separate flow with its own detection, caps ≤ Purpose, ≤ 7 days, ≤ 500 uses, and it is revoked automatically when the issuer is restricted, the epoch changes or the Purpose changes. | `tests/v5/delegation.test.mjs`. No campaign managed to grant one (harness and argument errors), so this is supported by unit tests only. |
| R-V5-03 | **Delayed attacker payments occupy the flow's pending slots and daily budget until the owner reviews them as FRAUD** (or until they expire after the delay). | A delay must not turn into a silent cancellation (F-V5-01). | The owner's FRAUD review (any UV) cancels them at once; the owner's other keys are separate flows. | Scenario A; campaigns. |
| R-V5-04 | **Availability cost during an incident: the owner's own payments on another key are delayed too.** After a security event the thresholds of every flow halve for 24 h (`securityCorrelationFactor` 0.5). In round 2, about half of the owner's 0.01 NEAR purchases on k2 (3 per hour) were delayed 6 h (`COLD_BURST_1H`, `BURST_NEAR_SECURITY_EVENT`). | Halving is what catches a thief who switches keys. | The delays are bounded (≤ 24 h); the payments settled afterwards (9 of 10 owner payments in round 2 burst_thief); Rapid-Use or a LEGITIMATE review releases them. Not tuned down: it would weaken detection. | `docs/evidence/v5/redteam/hardened/*-r2.json` → `owner.delayedReasons`. |
| R-V5-05 | **A thief holding the ORC plus one more owner key can CONTEST (revoke) a genuine owner key.** | CONTEST is the owner's tool; this attacker passes its authentication. | It needs both the ORC (offline hardware) and an independent owner credential through a trusted path; it cannot target a verified incident freeze; it never pays and never changes Purpose; it is journaled and e-mailed. | `tests/v5/anti-lockout.test.mjs`. |
| R-V5-06 | **A single stolen key can still impose up to 96 h of single-signer restriction per 30 days** (global provisional holds ≤ 24 h each, quarantines ≤ 72 h). | Protective actions must stay one tap for the genuine owner (R-V4-08). | Budget, max 3 active holds per issuer, and instant release of everything that depended only on the issuer when it is revoked or contested. | freeze_thief campaigns; anti-lockout tests. |
| R-V5-07 | **Vault liveness: a delayed payment expires instead of settling if the vault is down for longer than its window after `release_at`.** | The capability window is shifted by the delay, not extended indefinitely. | Safe (no early or late settlement outside the window); the owner simply pays again. | F-V5-01 notes; restart tests use 10-minute ticks. |
| R-V5-08 | **Rapid-Use explanation text (≤ 120 chars) is shown on the approving device and is requester-controlled.** | The approvers need the reason. | The device summary also states that Purpose, recipients and limits are unchanged, and the scope is bound exactly; the ORC + a separate credential must approve. | `commandSummary`. |
| R-V5-09 | **The journal is tamper-evident, not tamper-proof.** An administrator can delete the local file. | No external anchoring in this prototype. | Witness checkpoints detect deletion, truncation, reordering and modification. | `tests/v5/journal.test.mjs`. |
| R-V5-10 | **The Analyst can still be wrong or misleading in prose.** | It is a model. | Its output is schema-limited, OBSERVED metrics are recomputed, it cannot act, and reports label its narrative as non-authoritative. In the injection run it flagged the injections and changed nothing, but it filed one burst under `RAPID_USE_PATTERN` (wrong kind) and one claim was downgraded to UNSUPPORTED. | `docs/evidence/v5/analyst/analyst-injection.json`. |
| R-V5-11 | **Two mutations survive** (challenge single-use removed; Rapid-Use not skipping restricted scope credentials). | Judged redundant by reasoning, not proven: a grant is bound to the action digest, which contains a single-use action nonce, and a restricted credential can neither propose payments nor keep a delegation (auto-revoked on ISSUER_RESTRICTED), and the engine's R2 rule ends the grant. | Defence in depth kept. | `docs/evidence/v5/mutations.json`. |

## B. Unverified boundaries (simulated or not run)

| Boundary | Status |
|---|---|
| Trusted display (k3, k5, ORC), protected confirmation (k1, k4), WebAuthn UV | **SIMULATED** (in-process keys and renderer) |
| OS isolation of Root / Vault / Engine / Journal / Notify | **not run for V5**; logical isolation in one process only |
| E-mail | **MOCK transport only**; real provider `NOT_CONNECTED`; no real e-mail sent |
| Ledger / on-chain | MOCK ledger; **no Rust/contract parity for any V5 command**; no Testnet or Mainnet |
| Risk Policy Engine, report service, notification service, journal witnesses | in-process keys, not separately operated services |
| Detection quality | synthetic personas written by the implementer; **no real or independently held-out data** |
| CI | GitHub check suite on the PR head reported no failure; no runner-backed V5 job evidence beyond that |

## C. Harness limitations of the red-team campaigns

- The attacker is Claude Opus 4.8 confined to the General Zone action surface (`src/v5/redteam/actuator.mjs`) plus the
  scenario's stolen devices. It gets the public design and every error code; never owner keys outside the scenario,
  the ORC, the engine key, verifier output or ground truth.
- 10–12 virtual turns of 20 minutes each. In rounds 1–2 most multi-step attacks (build → sign → submit) died on
  `UNKNOWN_ACTION_REF` because the model numbered references per turn: 100+ wasted actions. This harness defect was
  fixed (`$this:K` same-turn references) before round 3. Rounds 1–2 therefore under-test command forgery and
  delegation abuse.
- **Safety-classifier stops:** some attacker calls ended with the provider's safety fallback (`SAFETY_STOP_FALLBACK`).
  The run stopped at that turn as required, and the stop is recorded; it was not retried, re-worded or bypassed, and no
  other model was substituted.
- The owner is a deterministic simulator. It reacts 1 h after the first alert (quarantine, revoke or contest, FRAUD
  review) and pays 0.01 NEAR every turn. Its early version mistook its own seeded history for foreign payments and
  revoked its own k2 in round 1 (fixed). That round-1 owner availability (6/10 and 4/11) is a harness artifact, not a
  system result.
