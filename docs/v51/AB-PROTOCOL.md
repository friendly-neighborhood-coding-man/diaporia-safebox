# V5.1 controlled comparison protocol (fixed before the full run)

**Primary comparison (prespecified by the mission):**

- **A, Control.** `bufferPolicy = FIXED_600`. Every payment waits 600 s. This is the frozen V5 baseline (93816b5) buffer policy, run on the V5.1 code (P1–P3 and the pending-slot repair), so the buffer is the only difference between the arms.
- **B, Candidate.** `bufferPolicy = EXP_30`, with `bufferSeconds(n) = min(600, 30 * 2^n)` and the deterministic tier `n` from `src/v5/risk/buffer.mjs`.

**Exploratory (does not decide anything):** `X_HV = EXP_30_HV`. This is EXP_30, except that a flow whose value over the last hour reaches half of the per-payment maximum always gets tier 5 (600 s). It was designed *after* the single-seed pilot (below) showed where B lost, so it is hypothesis-generating only. It would need a fresh confirmation on new trajectories before anyone relies on it.

**Matching.** Both arms run the same scenario code with the same seed list. That gives the same attack trajectories, the same legitimate payments and the same owner availability and response rules. The seeded PRNG drives jitter only, and no security decision reads it. Each arm gets the same 27 days of clean history for k1-phone (09/13/19 UTC) and k2-laptop (10/15 UTC). The exception is 02b, which reproduces the V5 Scenario A cold-start trajectory exactly. Ledger, e-mail, devices and time are all MOCK or simulated.

**Scenarios** (`src/v5/sim/v51-experiments.mjs`), numbered as in the mission:

1. Single max-value theft, with the owner discovering it at 2, 5 or 15 min, or never.
2. Fast burst, with the owner responding 30 min after the alert or offline. 02b is the preserved V5 40-second case.
3. Slow drain.
4. Splitting.
5. Baseline poisoning.
6. Genuine urgent payments, owner confirms or owner busy.
7. Recurring low-value payments.
8. Owner offline (mixed).
9. Mock e-mail outage.
10. Rapid-Use plus early end.
11. Freeze/Suspend at 3 min.
12. Expired / near-expiry authorizations.
13. Restart during a pending payment.
14. Competing flows for pending slots.

**Seeds:** 11, 23, 37, 41, 53.

**Acceptance, B vs A** (all must hold; computed by `scripts/v5/run-v51-ab.mjs`):

- **S1, invariants.** The independent verifier passes in every run of the arm, with 0 settlement-horizon violations and 0 unauthorized authority changes.
- **S2, attacker exposure.** In no matched run (same scenario and seed) does the candidate settle more attacker value than A. Tolerance is 0, because the mission treats the security boundaries as hard constraints.
- **L1.** The pooled legitimate success rate is ≥ A's.
- **L2.** The pooled legitimate p95 latency is strictly lower than A's.

Recommend B only if S1, S2, L1 and L2 all hold. Otherwise keep FIXED_600 and record the failed hypothesis.

**Disclosure.** These criteria were written down after a single-seed pilot run (seed 11) of A and B. The pilot already showed B settling extra attacker value in scenarios 01 (5 min), 05, 08, 11 and 14. The criteria follow directly from the mission text, and were not tuned in B's favour.
