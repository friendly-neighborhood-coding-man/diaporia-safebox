# Protective-hold protocol (Mission 2)

V4 had one global `freeze` flag. That meant that whoever lifted it lifted everyone's protection, and a recovery that
dropped the thief's freeze could also drop the owner's. V5 replaces the flag with **independent hold records**
(`src/v5/root/holds.mjs`, handlers in `src/v5/root/chain.mjs`).

## Hold record

`{holdId, class, scope {kind: GLOBAL|CREDENTIAL|MERCHANT|DELEGATION, target}, reason, issuers[], confirmers[],
evidenceClass, authDigest, createdAt, expiresAt | null, reinforces?, levels[], status, history[]}`

The **effective restriction** is the union of holds that are effective at time *t*
(`status === ACTIVE && (expiresAt === null || t < expiresAt)`). Expiry is a pure function of time, so the Root, the
vault replica and the verifier agree without a transition. `HOLD_EXPIRE` only records it. Removing one hold never
removes another.

## Severity classes

| Class | Who creates it | Duration | Release |
|---|---|---|---|
| TARGETED_QUARANTINE | one eligible owner credential (`SUSPEND` or `HOLD_CREATE`), one resource | ≤ 72 h | issuer, any valid party, expiry, contest, or every party revoked |
| PROVISIONAL_HOLD | one eligible owner credential; an owner `FREEZE` is a global PROVISIONAL_HOLD | ≤ 24 h unless confirmed | same as above |
| CONFIRMED_OWNER_HOLD | two independent owner credentials (distinct roles), or `HOLD_CONFIRM` by an independent credential | no expiry; 30-day review deadline (the deadline never auto-releases) | every still-valid party, **with a trusted confirmation** |
| VERIFIED_INCIDENT_FREEZE | only the independent supervisor (signed replay evidence), GLOBAL | never on a timer | owner quorum with a trusted confirmation **plus a repair certificate for this freeze**; never by contest, revocation or expiry |

Single-signer holds are bounded by an **issuer budget**: 96 h of single-signer restriction per issuer per 30 days, and at
most 3 active holds per issuer. A thief with one key cannot keep the account frozen indefinitely. The same issuer cannot
reinforce its own hold to stack time.

## Commands

`FREEZE`, `HOLD_CREATE`, `SUSPEND`, `HOLD_CONFIRM`, `HOLD_RELEASE`, `UNSUSPEND`, `HOLD_EXPIRE` (housekeeping),
`CONTEST_PROTECTIVE_HOLD`. Each command that acts on an existing hold binds `holdDigest`, which covers the id, class,
scope, issuers, creation time and authorization digest. A release that was signed for one hold cannot be used on another.

## CONTEST_PROTECTIVE_HOLD

`{contestId, holdIds, suspectCredId, reason}`. Personal profile: the **ORC plus an independent owner credential**
(not the suspect, not provisional), at least one through a trusted path. A suspended, but not revoked, surviving key may
sign this one command. Multi-admin profile: two other owners.

Effects:
1. revoke the suspect and bump the epoch (cancels its capabilities and pending payments);
2. release **only** the listed holds whose every credential party is now invalid. Holds that another valid party issued
   or confirmed are kept and logged as `CONTEST_REJECTED_OTHER_PARTIES`.

A contest cannot target a `VERIFIED_INCIDENT_FREEZE` or holds that the suspect did not issue. The suspect cannot sign it.
It never pays and never changes Purpose.

## Evidence

`tests/v5/anti-lockout.test.mjs` (15 tests, including the mandatory K1/K2 regression and its variants), mutations in
`docs/evidence/v5/mutations.json`, and the freeze_thief red-team campaign.
