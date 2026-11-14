# Command-bound authority (Mission 1)

## Rule

Every V5 authority-bearing command (holds, suspension, contest, incident review, delegation, Rapid-Use) is approved with a
**Command Statement**. The device signs the statement digest; the Root rebuilds the expected statement from **its own
state**, the submitted action and a one-time challenge grant, and requires **canonical byte-for-byte equality**
(`src/v5/root/command.mjs`, `verifyCommand`). V4 operations inside the V5 chain keep the V4 AuthorizationIntent (which
binds the same core fields) and are signed against the projected V5 state.

## Fields (COMMAND_FIELDS)

`v, protocol, accountId, chainId, credId, role, principal, commandType, actionDigest, paramsDigest, purposeId,
purposeVersion, matrixVersion, epoch, rootSeq, authorityDigest, affectedResources, caseRef, financialScope, operationId,
usageLimit, requiredLevel, summaryDigest, issuer, challengeNonce, sessionId, issuedAt, notBefore, expiresAt, actionExpiresAt`

- `authorityDigest` covers the V4 authority state plus every effective hold and Rapid-Use grant, so a statement signed
  before a hold changed no longer matches.
- `affectedResources` and `financialScope` are the exact resources and Purpose limits the command touches; the summary
  shown on the device is derived from the same function and its digest is bound (`summaryDigest`).
- `usageLimit` is always `1`; the challenge nonce is consumed by the transition (`CHALLENGE_ALREADY_CONSUMED`).

## Required confirmation level

| Command | Level |
|---|---|
| FREEZE, HOLD_CREATE, SUSPEND, HOLD_CONFIRM, HOLD_RELEASE, UNSUSPEND, INCIDENT_REVIEW (FRAUD), DELEGATION_REVOKE, RAPID_USE_REQUEST, RAPID_USE_REVOKE | ANY_UV (user verification on an enrolled authenticator). Protective, or reducing authority. |
| CONTEST_PROTECTIVE_HOLD, INCIDENT_REVIEW (LEGITIMATE) | ONE_TRUSTED: at least one signer through a trusted path (hardware display or protected confirmation). |
| DELEGATION_GRANT, RAPID_USE_APPROVE | TRUSTED: every non-ORC signer through a trusted path. The ORC is its own offline factor. |
| Release of a CONFIRMED_OWNER_HOLD or a VERIFIED_INCIDENT_FREEZE | handler requires a trusted signer (`anyTrusted`). |

Protective commands stay one-tap for the genuine owner (V4 R-V4-08 rationale); commands that *expand* or *release* power
need a trusted path.

## Delegated AI capabilities

`DELEGATION_GRANT` binds an agent key to: operation `PAY`, recipients ⊆ Purpose recipients, the Purpose asset,
per-operation and cumulative caps ≤ Purpose limits, `maxUses` ≤ 500, expiry ≤ 7 days and ≤ Purpose expiry, and the
mandatory revocation conditions `EPOCH_CHANGE`, `ISSUER_RESTRICTED`, `PURPOSE_CHANGE`. Each delegated operation is
signed by the delegate key over `{delegationId, seq, recipientId, asset, amountYocto, opId, issuedAt, memo}`; the vault
checks the grant on its replica, the sequence number, caps and uses, and the operation still passes the buffer and the
Risk Policy Engine (its own flow `dg:<id>`).

## Evidence

- `tests/v5/command-binding.test.mjs` (25 tests): a modified field in any position is rejected; replay, cross-command
  reuse, stale `rootSeq` / authority digest, wrong credential, wrong level are rejected.
- `tests/v5/delegation.test.mjs` (6 tests).
- Mutations (`docs/evidence/v5/mutations.json`): removing exact equality, single-use or the TRUSTED check is caught.
- Red team: `sign_forged` and `tamper` actions were available to the attacker model; see SECURITY-EVALUATION.md.
