# Anti-lockout (Mission 2)

## Mandatory regression (K1 / K2)

> A stolen K1 freezes the vault. The legitimate K2 independently places its own hold. The owner revokes K1.
> Expected: K1's hold stops restricting, K2's hold keeps the vault frozen, and only K2 (its issuer) can lift it.

`tests/v5/anti-lockout.test.mjs` → `MANDATORY: stolen K1 FREEZE, K2 independently holds, owner revokes K1 ...` passes:
after `REVOKE k1-phone` the K1 hold becomes `RELEASED_ISSUER_REVOKED`, the K2 hold stays `ACTIVE`, the vault stays frozen,
and `HOLD_RELEASE` by K2 lifts it.

Variants (all passing):
- K2 **confirms** K1's hold instead of creating its own. After K1 is revoked the hold stays (K2 is still a valid party)
  until K2 releases it.
- Reverse order (K2 first, K1 later).
- A multi-party hold needs every valid party to release it. One party cannot lift another party's hold.
- Three concurrent freezes from three credentials are released independently (union semantics).
- Reinforcement by the same issuer is refused, and the issuer budget bounds re-freezing.
- A provisional hold lapses at 24 h unless it is escalated. Escalation needs a distinct role and a trusted confirmation.
- A verified incident freeze is never released on a timer, by a contest or by issuer revocation.
- A supervisor breach hold and an owner hold are independent. Releasing the incident freeze leaves the owner's hold.
- The owner's own freeze survives revocation of an unrelated stolen key.
- The hold registry and the effective freeze survive Root and Vault restarts, because they are replayed from the chain.

## Bounds on a single stolen key

| Lever | Bound |
|---|---|
| Global freeze by one key | PROVISIONAL_HOLD, ≤ 24 h, then expires |
| Quarantine of another key | TARGETED_QUARANTINE, ≤ 72 h |
| Total single-signer restriction per issuer | 96 h per 30 days, ≤ 3 active holds |
| Undo | revoke or contest the issuer: every hold that depended only on it stops counting immediately |
| Releasing the owner's holds | impossible: the owner's holds have the owner's keys as parties |

## What anti-lockout does NOT promise

- A thief holding the **ORC plus another key** can contest the owner's key (CONTEST is the owner's tool, and that
  attacker passes its authentication). See RESIDUAL-RISKS.md R-V5-05.
- Payments are interrupted while any effective GLOBAL hold exists. The owner interrupts the interruption by revoking or
  contesting the issuer, which takes the ORC or the V4 revoke quorum.
