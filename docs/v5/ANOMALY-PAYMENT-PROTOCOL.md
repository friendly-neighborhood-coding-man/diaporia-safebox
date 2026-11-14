# Anomaly payment protocol (Mission 4)

## What the system may do automatically

Exactly one financial reaction is automatic: a **bounded ANOMALY_PAYMENT_DELAY of specific, still-unsettled payments of
one flow**. A flow is one payment credential (`cred:<id>`) or one delegated capability (`dg:<id>`). Nothing else is
automatic. The Risk Policy Engine cannot freeze, suspend, revoke, release, approve, change Purpose, or start or extend
Rapid-Use (`src/v5/risk/engine.mjs`).

## Decision path

1. The vault accepts a proposal only with a valid capability (unchanged V3/V4 rules), then puts it in the 10-minute buffer.
2. The engine evaluates the payment with `RISK_POLICY_V1` (`src/v5/risk/detector.mjs`): deterministic features per flow
   over 10 min / 1 h / 24 h windows, compared with three references:
   - cold-start priors derived from the Purpose limits (fewer than 20 clean payments or less than 7 days of history);
   - a flow baseline learned **only** from clean history: settled at least 72 h ago, never delayed, never under Rapid-Use,
     never in an incident, and never within 24 h after a security event. The baseline grows at most 1.5× per 14 days;
   - absolute ceilings no baseline can raise: 6 per 10 min, 15 per hour, 40 per 24 h, 40 % of the remaining daily
     limit per hour, 20 % of the remaining cumulative limit per 24 h.
3. The engine signs `{paymentId, flow, action, delayMs, policy, policyDigest, evaluationDigest, incidentRef}`. The vault
   verifies the signature against the pinned engine key (`ENGINE_DECISION_SIGNATURE`) and caps the delay at 24 h,
   whatever the engine asks.
4. On DELAY the vault pushes `release_at` by the delay (6 h, or 24 h after 3 delayed payments in the open incident),
   opens or extends an incident, delays the flow's other unsettled payments, journals `PAYMENT_DELAYED`, and
   e-mails every key holder (NOTIFICATION-POLICY.md). Recipient, amount, asset, Purpose and authorization are unchanged.
5. **F-V5-01 fix:** the delay also shifts the capability's expiry window by the same amount (`cap_expires_orig` is
   kept). Before the fix a delayed payment silently expired, which turned a delay into a cancellation.
6. The owner decides the incident with `INCIDENT_REVIEW`:
   - **FRAUD** (any UV) cancels the flow's delayed payments.
   - **LEGITIMATE** (needs a trusted confirmation) releases them.
   - An undecided delay simply ends at `release_at`, and the payment then settles if everything else still holds:
     epoch, credential, holds, Purpose.

## Independent checks

The verifier (`src/v5/supervisor/verifier.mjs`) recomputes, for every ledger transfer:
- `DELAY_WITHOUT_ENGINE_DECISION`: a delay must have a signed engine decision;
- `DELAY_OVER_CAP`;
- `DELAYED_PAYMENT_RELEASED_EARLY`: an early release needs a LEGITIMATE review or a covering Rapid-Use grant;
- `DELAY_RECORD_MISMATCH`: the vault's delay must match the engine's own journaled `ENGINE_DECISION` (RISK layer);
- `BUFFER_BYPASSED`, `EFFECT_AFTER_CAPABILITY_WINDOW`, and the Purpose checks.

## Measured (see SECURITY-EVALUATION.md)

- Scenario A (stolen k1, 0.05 NEAR every 20 s): first delay at 40 s, first e-mail at 60 s, 0 settled before detection,
  16/16 attacker payments cancelled by the FRAUD review.
- Labelled trajectories (synthetic, written by the implementer): 0 false positives in 30 benign runs, 40/40 malicious
  runs detected. Slow drains below the thresholds settle payments before detection; see RESIDUAL-RISKS.md R-V5-01.

## Liveness note

A delayed payment is released by the vault's tick. If the vault is down for longer than the payment's remaining window
after `release_at`, the payment expires instead of settling. That is safe, but not live (R-V5-07).
