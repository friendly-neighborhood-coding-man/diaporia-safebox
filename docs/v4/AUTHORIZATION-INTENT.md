# AuthorizationIntent, deterministic summaries and challenges (mission §6, §7, §9)

Code: `src/v4/intent/intent.mjs`, `src/v4/intent/summary.mjs`, delegate in `src/v4/root/chain.mjs`.
Tests: `tests/v4/intent-ui.test.mjs`, `tests/v4/mutation-kills.test.mjs`.
Verification level: **deterministic mock verified** (in-process), **software-authenticator verified** for WebAuthn passkeys (`src/v3/webauthn/soft-authenticator.mjs`), **local contract verified** for the on-chain subset (`contract-v4`).

## Which actions need an intent

`INTENT_REQUIRED` (high-risk): AMEND_PURPOSE, AMEND_MATRIX, UNFREEZE, ROTATE, REVOKE, REPLACE_VACANT, UNSUSPEND, RATIFY_BASELINE, RECOVERY_CONSENT, RECOVERY_WITHDRAW, RECOVERY_CANCEL, RECOVERY_OWNER_AUTHORIZE, RECOVERY_ORC_CANCEL, RECOVERY_OPEN (ORC attestation), ORC_REPLACE, GOV_CASE_OPEN, GOV_CASE_CANCEL, GUARDIAN_ROTATE. A V3 action-digest approval for any of these fails with `AUTHORIZATION_INTENT_REQUIRED`.

Protective actions (FREEZE, SUSPEND, RECOVERY_OBJECT) still accept V3 action-digest approvals, so the owner can always stop things quickly, including from a device without a trusted display.

`CRITICAL` actions (AMEND_PURPOSE, AMEND_MATRIX, ROTATE, REPLACE_VACANT, RATIFY_BASELINE, RECOVERY_OWNER_AUTHORIZE, ORC_REPLACE, GOV_CASE_OPEN, GUARDIAN_ROTATE) additionally need at least one approval whose confirmation level is trusted (`TRUSTED_DISPLAY_SIM` or `PROTECTED_CONFIRMATION_SIM`).

## The intent

Canonical JSON (sorted keys, strings only), hashed with SHA-256 under the domain `V4_DOMAINS.INTENT`. Fields (`INTENT_FIELDS`):

| Field | Binds |
|---|---|
| v, protocol | format and protocol version |
| accountId, chainId | the account and the exact Root chain (genesis digest) |
| purposeId, purposeVersion, matrixVersion | the Purpose and the authority matrix in force |
| actionType, actionDigest, paramsDigest | the exact action (type, header nonce, body) |
| epoch, rootSeq, authorityDigest | the authority state: epoch, credential / guardian / IDV / ORC sets with key digests, matrix, Purpose, open case and governance-case digests, freeze and lockdown |
| caseId | the recovery or governance case the action belongs to |
| newKeyDigests | every public key the action would install (plan keys, new credential, new ORC, replacements) |
| summaryDigest | digest of the deterministic summary the person sees |
| issuer, credId, challengeNonce, sessionId, issuedAt, notBefore, expiresAt | the one-time grant |
| screenDigest | `-`, or the digest of the rendered authorization region (evidence only) |

The Root never trusts the submitted intent. It recomputes the expected intent with `buildIntent(state, action, grant, {rootSeq, screenDigest})` and requires canonical equality (`INTENT_MISMATCH` lists differing fields). `rootSeq` may be older than the head only if the authority digest is unchanged, so an approval prepared a few transitions earlier stays valid while any authority change makes it stale.

Signatures: passkeys sign the intent digest as the WebAuthn challenge (UV required); hardware keys and the ORC sign it with Ed25519 under the intent domain.

## Deterministic summaries (§6)

`buildSummary(state, action)` produces a structured object from verified state only: title, account, action, reason, case, removes, adds (with key digests), affected participants, resulting authority, Purpose changes, payment changes, reversibility, delay, side effects (epoch bump, retirement of all credentials on reconstitution), expiry and a scope sentence ("This approval authorizes ... and nothing else"). `renderText` turns it into the exact lines a trusted display shows; `renderScreen` produces a fixed-width "framebuffer" of the dedicated authorization region.

Free text from the requester is never presented as a fact. A REVOKE reason renders as `requester note (unverified, not part of the effect): ...`, so a requester cannot present an instruction such as "approve this" as part of the effect. AI-provided text cannot reach the summary in any other field.

## Challenges (§9)

| Property | Implementation |
|---|---|
| Unpredictable | 256-bit nonce from `crypto.randomBytes(32)`, format-checked `^[0-9a-f]{64}$` |
| Short-lived | lifetime ≤ `challengeTtlMs` = 120 s (config range 30–300 s), checked against Root time with 60 s skew for issuance only |
| Action-bound | grant statement binds accountId, chainId, actionType, actionDigest and credId; signed by the enrolled challenge issuer |
| Single-use | `s.v4.usedChallenges[nonce]` written in the same transition that consumes it, so a failed transition consumes nothing and a committed one is persisted; a Root restart replays it |
| Rate-limited | the issuer refuses more than `maxPerCredPerHour` grants per credential |
| Separate from recovery timers | the 120 s grant lifetime is unrelated to the 72 h case window, 12 h cooldown or 24 h governance delay |

## Tests that pin this

- every intent field changed and consistently re-signed is refused with `INTENT_MISMATCH` (full quorum, fresh grant): `tests/v4/mutation-kills.test.mjs`
- approve A, execute B; stale approval after an authority change; expired / future / too-long / forged-issuer / other-account / other-credential / replayed grants; rate limit; racing submissions; restart: `tests/v4/intent-ui.test.mjs`
- single use independent of the action nonce: `tests/v4/mutation-kills.test.mjs`
- on-chain: `contract-v4/src/tests.rs` (`v4_governance_challenge_needs_256_bit_nonce_short_lifetime_not_future`, `v4_orc_intent_bound_to_operation_case_time_key_and_single_use`)

Mutation evidence: `docs/evidence/v4/mutations.json` (19/19 caught after the targeted tests; first run `mutations-run1.json` 15/19).
