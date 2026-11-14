# Rapid-Use Mode (Mission 4)

The genuine owner sometimes needs the very pattern the detector delays: many in-Purpose payments in a short time.
Rapid-Use Mode removes the **anomaly delay only**, for an approved scope, for **at most 24 h**. It never changes Purpose,
recipients, the asset or any limit, and it never removes the 10-minute buffer.

## Flow

1. `RAPID_USE_REQUEST {requestId, scope, delayException: "REMOVE_ANOMALY_DELAY", durationMs ≤ 24 h, explanation, incidentId}`.
   One owner credential signs it (ANY_UV). Scope: `credIds`, `delegationIds`, `recipients` ⊆ Purpose, asset, Purpose id
   and version, the Purpose limits copied unchanged, and an optional `sessionCapYocto`. Rate limits: 3 requests per
   credential per 24 h, one pending request per credential, and a 1-hour approval window.
2. `RAPID_USE_APPROVE {requestId, requestDigest, decision}` votes. The quorum depends on the profile:
   - **Personal profile:** the ORC plus a separate owner credential that is not in the scope (the bursting key cannot
     vouch for itself: `RAPID_FACTOR_IS_AFFECTED_CREDENTIAL`), and every non-ORC vote through a trusted path.
   - **Multi-owner profile:** `max(2, ceil(N/2))` distinct human owners. Several keys of one human count as one vote
     (`RAPID_DUPLICATE_PRINCIPAL_VOTE`), and FREEZE / RECOVERY roles are not voters.
3. `RAPID_USE_ACTIVATE` (anyone may submit it once the quorum is met). It is refused if a scope credential is not
   active, if an active grant already covers the flow, or if more than 3 activations happened in 7 days.
4. While the grant is active, the vault does not apply anomaly delays to covered payments and releases that flow's
   already-delayed payments (`RELEASED_BY_RAPID`). The engine keeps monitoring.
5. **End Rapid-Use Mode** happens in one of four ways:
   - the owner's `RAPID_USE_REVOKE {grantId, reason}` (any UV);
   - the engine's predefined rules, with an engine-signed attestation: R1 scope exploit, R2 scope credential restricted,
     R3 velocity ceiling 90 per hour (F-V5-03);
   - expiry (`RAPID_USE_EXPIRE`);
   - an epoch or Purpose change.
   After the end, payments are delayed again.

## Bounds

- **Duration:** the 24 h ceiling is enforced at the Root (`RAPID_DURATION_MAX_24H`). Nothing renews a grant. The verifier
  flags any window longer than 24 h.
- **Velocity:** the velocity ceiling is 90/h. The vault's 16 pending slots × 10-minute buffer already cap throughput at
  about 96/h, so a ceiling above that is unreachable. The first ceiling of 30/h ended a genuine Scenario B session
  (F-V5-03).

## Measured

- Scenario B (personal): 34/34 legitimate payments settled, 16 accelerated by Rapid-Use; 620 s delay before
  authorization; payments after End are delayed again.
- Scenario B (multi-owner, N=4): see `docs/evidence/v5/scenarios.json`.
- Scenario D (30 malicious approval attempts): 0 unauthorized activations.
