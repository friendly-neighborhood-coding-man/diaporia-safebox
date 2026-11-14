# SafeBox V5.1 security evaluation

**Decision: keep the fixed 600 s settlement buffer (`FIXED_600`). The adaptive exponential buffer (`EXP_30`) is a
failed hypothesis.** It made legitimate payments faster (p50 600 s → 300 s) but let the attacker settle more value
(2.4 → 3.5 NEAR across the matched runs), and it failed the prespecified acceptance criterion S2 on 25 matched runs.

Everything here is a deterministic simulation in one process: MOCK ledger, MOCK e-mail, simulated devices, a simulated
clock. Nothing was run on real hardware, an OS-separated deployment, Testnet or Mainnet. No real funds were moved and
no real e-mail was sent. There is no Rust parity for V5/V5.1.

## Candidates

| Step | Commit | Content |
|---|---|---|
| V5 baseline (frozen) | `93816b5` | Draft PR #7, unchanged |
| P1–P3 | `3b14679` | no-owner-response resolution (HIGH/LOW), owner-signed 26 h settlement horizon, mutation-survivor evidence |
| P4 (separate) | `8ab0cd1` | experimental `EXP_30` buffer and matched A/B harness |
| repair | `ee2371b` | a flow under an open incident holds at most 8 of the 16 pending slots |
| A/B runner | `00af140` | exploratory `EXP_30_HV`, prespecified protocol, Rapid-Use lifts the per-flow cap |
| P4 kill tests | `36bef95` | tests for the 3 surviving P4 mutants |
| verifier repairs 1 | `5765ae6` | F1–F4, F6, F7 (independent verification round 1) |
| verifier repairs 2 | `257e6fb` | N1–N5 (round 2) |
| verifier repair 3 | `de43b53` | R8 hidden open incident (round 3) |
| final | `f22cc26` | mutants for the repairs + F1 kill test (src identical to `de43b53`) |

```
npm test                                                     # 476/476 at f22cc26 (V1..V5.1)
GIT_COMMIT=<sha> node scripts/v5/run-v51-ab.mjs              # -> docs/evidence/v51/ab-results.json, ab-summary.md
node scripts/v5/mutations.mjs docs/evidence/v51/mutations.json   # ONLY in a separate git worktree (it edits src/)
```

The V1–V5 evidence is unchanged (`git diff 93816b5 -- docs/evidence/v5` is empty).

## P1: no owner response

- An incident's risk class is deterministic: HIGH if the detector reports a hard rule, a score of at least twice the
  delay threshold, a security-correlated DELAY, or an incident already HIGH or escalated by its own triggers. Otherwise LOW.
- LOW: the payment waits its bounded delay and then settles, after Purpose, credential, Epoch, holds and the
  authorization are re-checked at release.
- HIGH: if the owner has not resolved it (a trusted LEGITIMATE review of that incident, or a Rapid-Use grant covering
  the payment), the payment EXPIRES (`HIGH_RISK_UNRESOLVED`) and needs a new authorization. Nothing else is frozen.
- Scenarios: owner offline, e-mail outage, 6/24/72 h owner absence, slow drain. 0 HIGH payments settled without
  resolution in any run. In slow drain (03) the attacker settles 1 NEAR in both arms before the first detection (3185 s).

## P2: settlement horizon

- `settlementHorizonMs` = 26 h is in the genesis that every owner device and the ORC sign.
- The vault keeps four times separate:
  - submission deadline: the authorization's own expiry, checked at proposal;
  - consumption: when the vault accepts the payment;
  - earliest release: buffer plus any bounded anomaly delay;
  - latest settlement: `issuedAt + horizon`, capped by the Purpose expiry.
- A delay never moves the latest settlement. A payment whose delay would end after it expires unsettled.
- The verifier recomputes the horizon from the replayed genesis and the signed `issuedAt` (`EFFECT_AFTER_SETTLEMENT_HORIZON`).
- Result: 0 horizon violations in all arms.

## P3: the two V5 mutation survivors

Both are **redundant checks (defence in depth), not necessary ones**:

- **Challenge single-use.** Replays are already stopped by ACTION_REPLAY (Root nonce), DUPLICATE_APPROVAL, the WebAuthn
  sign counter and the authorityDigest binding.
- **Rapid restricted-credential check.** The Root's `normalizeRapid` already ends the grant at the suspending
  transition.

Each is now killed by a white-box layer-isolation test that removes the other layers. The challenge test now uses the
Ed25519 hardware key, which has no sign counter. These tests show each layer works on its own. They do not show that the
system needs it. We do not claim system-level necessity.

## P4 and the controlled A/B

The protocol is in `docs/v51/AB-PROTOCOL.md`. Its acceptance criteria were fixed after a single-seed pilot and before the
full run; this is disclosed there.

- **Arms.** A = `FIXED_600`; B = `EXP_30`, `bufferSeconds(n) = min(600, 30·2^n)`.
- **Tier.** `n` is a deterministic, bounded tier from signed inputs:
  - flow value over the last hour relative to the per-payment maximum, so splitting a payment does not lower the tier;
  - daily and cumulative budget use;
  - 10 min and 1 h frequency;
  - cold start or deviation from the baseline;
  - correlated security events and an open incident;
  - the detector level;
  - a sticky floor: never below the flow's highest tier in the last hour.
- X_HV is exploratory only and decides nothing.
- **Runs.** 5 seeds × 21 scenario variants (the 14 mission scenarios, with discovery-time and owner variants), matched
  run by run. The seeds gave identical trajectories: the PRNG drives only jitter, so this is effectively 1 run per
  variant, repeated 5 times.

| Metric (all runs pooled) | A: FIXED_600 | B: EXP_30 | X_HV (exploratory) |
|---|---|---|---|
| attacker settled, NEAR (attack scenarios) | **2.4** | **3.5** | 2.45 |
| attacker settled before first detection, NEAR | 2.4 | 3.5 | 2.45 |
| legitimate success | 470/485 (96.9 %) | 470/485 | 470/485 |
| legitimate latency p50 / p95 / p99, s | 600 / 22260 / 87120 | **300** / 22080 / 87120 | 600 / 22260 / 87120 |
| false-positive delays / cancellations | 90 / 0 | 75 / 0 | 90 / 0 |
| pending-slot exhaustion | 0 | 0 | 0 |
| owner prompts | 90 | 90 | 90 |
| horizon violations / unauthorized authority | 0 / 0 | 0 / 0 | 0 / 0 |
| verifier ok, every run | yes | yes | yes |
| engine decision p99 / journal bytes per run (mean) | ≤ 200 ms / 60.8 kB | ≤ 100 ms / 61.3 kB | — |

**Acceptance for B:**
- S1 (invariants): pass.
- **S2 (no matched run with more attacker settlement): fail, 25 runs.** The affected scenarios, each on every seed:
  - 01 single max theft discovered at 5 min: 0 → 0.3 NEAR;
  - 05 baseline poisoning: 0.5 → 0.75;
  - 08 owner offline mixed: 0 → 0.25;
  - 11 freeze at 3 min: 0 → 0.25;
  - 14 competing slots: 0 → 0.05.
- L1 (success not worse): pass.
- L2 (p95 improved): pass, 22260 → 22080 s.
- **Rejected.**

The mechanism: under B, a low-tier payment leaves after 30–240 s, before the owner's 2–5 min discovery or freeze. Under A
it is still waiting at 600 s.

**The 40-s detection case** (02b, V5 Scenario A, cold start, detected at 40 s): no extra settlement under B. The detector
fires before the 30 s floor matters.

X_HV removes most of B's loss (2.45 NEAR) but also removes its latency gain (p95 unchanged). It fails S2 on 5 runs and L2.

The p95/p99 tails come from the 6–24 h anomaly delays on owner-busy flows (06, 08), not from the buffer. No buffer policy
changes them.

The 15 legitimate refusals:
- 5 × `PAYCAP_EXPIRED` in scenario 12, by design;
- 2 per run in scenario 10, after Rapid-Use ended, from the per-flow incident cap.

"Before detection" counts payments proposed before the first engine detection on the attack flow. In these scenarios
all attacker settlement falls in that window.

## Independent verification (implementer did not self-certify)

A separate agent with no implementation role verified the candidate in three rounds, writing its own adversarial probes.

| ID | Sev. | Finding | Repair | Status |
|---|---|---|---|---|
| F1 | HIGH | P1 verifier relied on the vault's `incident_id` | HIGH coverage from the engine's RISK journal and flows from owner-/delegate-signed evidence | closed |
| F2 | HIGH (EXP_30) | engine failure after the V3 reservation released at the floor, unevaluated | fail closed: cancel (`ENGINE_EVALUATION_FAILED`), at runtime and on restart | closed |
| F3 | MED | buffer check trusted `v5_pay` rows and `proposed_at` | effect needs a V5 record and the journaled `BUFFER_DECISION`; proposal time from the journal; buffer = max(signed, journaled) | closed |
| F4 | LOW/MED | tier-reset check used vault flow and times | runs on the journal with signed flows | closed |
| F6 | LOW | delegated `issuedAt` not bounded in the verifier | [proposal − 10 min, proposal + 5 min] | closed |
| F7 | INFO | mutations default path; null p95 counted as 0 | `docs/evidence/v51`; null never passes L2 | closed |
| N1 | HIGH | tx could spend cap X under another payment id Y (borrowing Y's record) | `EFFECT_CAP_NOT_BOUND_TO_PAYMENT` | closed |
| N2 | MED | crash after the `v5_pay` insert left a half-evaluated payment at the floor | `evaluated` marker; incomplete evaluation is cancelled | closed |
| N3 | MED | any LEGITIMATE review of the credential resolved HIGH | incident ids derived from the opening payment; the review must name that incident; foreign or closed `incidentRef` flagged | closed |
| N4 | MED (false positive) | honest settlement of a reviewed LOW incident was flagged after a later HIGH incident | per-incident binding | closed |
| N5 | LOW | verifier ok without the engine journal | `ENGINE_JOURNAL_REQUIRED` | closed |
| R8 | MED | vault hides an open incident from the engine and gets NONE decisions | incident lifetimes rebuilt from the journal; `ENGINE_CONTEXT_OMITTED_OPEN_INCIDENT` | closed |

Each repair has a regression test (`tests/v5/verifier-independence.test.mjs`, `tests/v5/buffer.test.mjs`). The F1, F3, F4
and F6 tests were run against the pre-repair verifier and fail there. N1–N5 and R8 were reproduced on the pre-repair
code by the independent verifier's own probes. Each repair is also pinned by a mutant (below).

## Mutation testing

`docs/evidence/v51/mutations.json`: **48/48 first-order and 4/4 higher-order mutants caught.**

- The full run was at `de43b53`. The mutants for the repairs were run at `9d5773b` and `f22cc26`; product `src/` is
  identical across these commits.
- The V5 fail-safe mutant was retired because the code it targeted was replaced by the F2 cancellation and retargeted.
- The two V5 survivors are caught only by layer-isolation tests (see P3).

## Residual risks (open)

- **E1 (LOW).** A compromised vault can hide an open incident in the last 15 min of its 24 h lifetime. That is the
  verifier's tick slack, and the verifier does not detect it.
- **E3 (LOW, reasoned, not reproduced).** With two open incidents on one flow (after `DELAY_AND_END_RAPID`), the verifier
  accepts a reference to either one.
- **Rapid-Use coverage (LOW–MED, from reading the code).** The verifier does not check the grant's `sessionCapYocto`,
  amount or asset. A compromised vault could keep treating payments as Rapid-covered beyond the cap while an
  owner-approved grant is active.
- **Structural: the engine trusts context the vault supplies.** The verifier cannot recompute these:
  - payment history (rates, baseline, cold start, sticky tier inputs);
  - spent amounts;
  - security-event times;
  - fields of an open incident (escalation counts);
  - the vault's sweep of other pending payments when an incident opens;
  - the decision clock.

  The verifier checks that the signed tier follows from the signed inputs, not that the inputs are true.
- **F5 (LOW).** The Rapid-Use exemption from the per-flow cap allows filling the global 16 slots. It requires ORC plus a
  hardware key.
- **Availability (from V5, R-V5-04).** The owner's own payments are delayed during an incident.
- **Simulation limits.** A non-adaptive scripted attacker (no LLM red team in V5.1). Identical seeds. Everything is
  MOCK or simulated.
