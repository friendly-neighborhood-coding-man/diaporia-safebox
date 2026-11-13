# SafeBox V3 architecture: Immutable Purpose Root, five credentials, Recovery V0

Status: research prototype on Draft PR #5. It is stacked on V2-B and must never be merged. It does not touch Mainnet,
real assets, or live private credentials. No Testnet transaction was made.

## 1. What V3 adds to V2-B

| Layer | V2-B (kept as is) | V3 (new) |
|---|---|---|
| Financial path | Exact-amount buffered release, trusted repair replay (F-B01..F-B03 fixes), MockLedger, SensitiveStore | The same vault, now driven by a **Purpose Root replica** instead of a static policy |
| Authority | One owner key + supervisor | **Five independent credentials** (K1..K5), role matrix, epochs, rotation and revocation |
| Recovery | none | **Recovery V0** state machine with guardians, identity verification, objection window, lockdown and reconstitution |
| Human presence | owner signature | **WebAuthn RP verification** (UV/UP, origin, RP ID, challenge = action digest, signCount) |
| Chain | NEAR contract V1 (payment only) | `contract-v3`: on-chain re-enforcement of purpose, roles, epochs and recovery (local only) |
| OS | V2 zones (sup/sens/ledger/gen) | Five V3 principals: root, recovery, vault, ledger, general zone (privilege matrix) |

## 2. Components and trust

```
 Owner devices (K1 phone passkey, K2 laptop passkey, K3 root HW ed25519, K4 freeze passkey, K5 recovery HW ed25519)
        │ signed actions (domain-separated, canonical, digest-bound)
        ▼
 ┌──────────── Purpose Root service (sbx3-root) ────────────┐       ┌── Recovery service (sbx3-recov) ──┐
 │ append-only SQLite hash chain; compare-and-append; pure  │◄─────►│ notifies every channel; can submit │
 │ deterministic applyTransition(state, transition)         │ port  │ only DISPATCH / COMPLETE /         │
 │ ports: admin (SUBMIT, VIEW), replica feed, recovery      │       │ RECONSTITUTE; its key is no        │
 └──────────────────────────┬───────────────────────────────┘       │ credential and approves nothing    │
                            │ transitions (replica feed)            └────────────────────────────────────┘
                            ▼
 ┌──────────── Execution Vault (sbx3-vault) ────────────────┐       ┌── Ledger (sbx3-ledger) ──┐
 │ replays the chain itself (pinned genesis digest);        │──────►│ MockLedger (V2)          │
 │ alarms + freezes on fork / rollback / time-ahead;        │       └──────────────────────────┘
 │ verifies PAYCAP + approval against ITS replica state;    │
 │ exact recipient/amount/asset; buffered release with      │
 │ re-check (epoch, purpose version, approver status)       │
 └──────────────────────────▲───────────────────────────────┘
                            │ gz port: PROPOSE, STATUS, HEALTH, ROOT_VIEW only
 ┌──────────── General Zone (sbx3-gen, no network) ─────────┐
 │ the AI agent; holds no credential, no root port          │
 └──────────────────────────────────────────────────────────┘
 Independent verifier (src/v3/supervisor/verifier.mjs): replays the chain from genesis and checks each ledger effect
 against the cap evidence and the authority state at that time.
```

The **trusted computing base** is:
- the Root transition function (`src/v3/root/chain.mjs`) plus its canonical encoding;
- the vault's replica and release checks;
- the pinned public keys;
- the OS launcher;
- the owner's authenticators.

The AI agent, the recovery service, notification channels, and any single guardian or identity verifier are
**outside** the TCB. None of them alone can change authority.

## 3. The Purpose Root

- **Capsule** (`src/v3/root/capsule.mjs`). This is a signed, canonical object. It contains:
  - the immutable identity fields: `purposeId`, `accountId`, `principalId`, `statement`, `asset`, `allowedOperations`;
  - the amendable limits: recipients, per-payment, cumulative and daily limits, SKUs, and expiry.
  
  Rules:
  - Amendments bump `version`.
  - Amendments may only strengthen the purpose, unless the full governance quorum signs.
  - The immutable fields can never change.
- **Canonical encoding** (`src/v3/common/canon.mjs`):
  - Only objects, arrays and ASCII strings are allowed, with no numbers and no booleans. So an AI-supplied
    `biometricVerified: true` cannot even be encoded.
  - Keys must match `/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/`. Maximum depth is 10.
  - Every signature covers `domain || sha256(canon(x))`. There are 14 V3 domains (ACTION, PAYCAP, CAPSULE,
    MATRIX, TRANSITION, GUARDIAN, IDENTITY, OFFICIAL, CHANNEL, DISPATCH, REPAIR, SUPERVISOR_FREEZE, ENROLL,
    LEDGER_TX). A signature for one purpose cannot be replayed as another.
- **Action envelope.** Each action binds:
  - `chainId` (the genesis digest), `accountId`, `epoch` and `rootSeq`;
  - a 128-bit nonce, `notBefore` and `expiresAt` (at most 96 h, with ±5 min skew).

  The action digest is the WebAuthn challenge. Nonces are single-use per chain.
- **Chain.**
  - `transitionHash = H(prev, seq, at, action, approvals, attestation)`.
  - `replayChain` rebuilds the state from genesis and rejects any gap, fork, or hash mismatch.
  - The Root, the Vault and the verifier each replay the chain independently.
  - A Root store that is rolled back, forked, or has tampered rows is detected by the vault replica, which alarms and
    freezes. On restart the Root itself fails closed if its own rows don't re-hash.

## 4. Five credentials and the authority matrix

| Credential | Kind (personal profile) | Can | Can never |
|---|---|---|---|
| K1 daily (phone) | passkey, UV | PAY; co-sign governance | amend alone |
| K2 daily (laptop) | passkey, UV | PAY; co-sign governance | amend alone |
| K3 root (hardware) | ed25519 | governance with K1+K2; unfreeze with a daily key | PAY |
| K4 freeze | passkey | FREEZE alone | UNFREEZE, PAY, amend |
| K5 recovery (hardware) | ed25519 | recovery consent; co-sign K5 rotation | PAY, amend |

The matrix (`src/v3/authority/matrix.mjs`) maps role counts to actions.
- It has pseudo-roles `SELF` (the subject credential itself) and `ANY`.
- Default rules:
  - `AMEND_PURPOSE` and `AMEND_MATRIX` = 2×DAILY + ROOT, with UV.
  - `UNFREEZE` = ROOT + DAILY.
  - `REVOKE` = DAILY+ROOT or 2×DAILY, and never self-approved.
  - `ROTATE_*` needs SELF plus role-specific others. Rotating K5 additionally needs the guardian quorum.
- **Hard floors** (`floorViolations`) cannot be amended away, even with the full governance quorum:
  - governance stays at ≥ 3 keys;
  - FREEZE can never unfreeze;
  - ROOT/RECOVERY rotation, revocation and lockdown-cancel need ≥ 2 keys;
  - recovery consents are single-signer.
- Amendments are strengthen-only and must stay satisfiable.

**Multi-administrator profile.** Here governance is ADMIN:3 counted by **distinct holders**, so five keys of one person
never count as three administrators. A deceased or missing administrator is replaced through an evidence review. That
review needs:
- a registrar-signed certificate;
- identity verification;
- guardians;
- the window.

A police report alone grants nothing.

**Independence** (`src/v3/authority/enroll.mjs`). Genesis and every plan refuse:
- duplicate credential IDs or public keys;
- duplicate WebAuthn credential IDs;
- a shared seed, a shared device, or a shared sync provider.

Enrollment requires proof of possession over an enrollment challenge.

**Epochs.** Rotation, revocation, vacancy replacement, recovery and reconstitution each bump the epoch. Every
capability and buffered payment carries its epoch. The vault cancels anything stale at release time.

## 5. WebAuthn / passkey injection port

`src/v3/webauthn/verify.mjs` is a relying-party verifier with a strict CBOR decoder. It checks:

- **Registration:**
  - `none` and `packed` self-attestation are accepted; `x5c` chains are rejected (no attestation trust store);
  - origin, RP ID hash, challenge, and the UP/UV flags.
- **Assertion:**
  - the exact fields `credentialId`, `authenticatorData`, `clientDataJSON`, `signature` (and optionally `userHandle`);
  - `type = webauthn.get`, origin, `crossOrigin=false`, RP ID hash, challenge = action digest;
  - the ES256 signature;
  - signCount must strictly increase, so a cloned authenticator is caught.

UV is **reported** as "user verification performed by the authenticator". It is never described as "biometric
checked". No biometric data is received or stored. Any boolean from the AI or the request body is ignored. UV is
required only where the matrix says so, which is for multi-signer rules. Single-signer recovery consents from ed25519
hardware keys have no UV. This was a usability finding during development.

## 6. Vault and payments

- A payment needs a **PAYCAP**. It is:
  - signed by a DAILY credential (WebAuthn assertion with challenge = paycap digest);
  - bound to purpose ID and version, epoch, recipient, exact amount, asset, SKU, a UUIDv4 capability ID, nonce and
    expiry.
- The vault verifies the PAYCAP against **its own replica**. It enforces purpose limits and exact-amount matching
  (the V2-B F-B01 fix), then buffers the payment for `bufferMs`.
- At release it re-checks epoch, purpose version, approver status, freeze and lockdown.
- The V2-B trusted-repair replay (F-B02/F-B03) and SensitiveStore are reused unchanged. Their tests still pass in the
  full suite.

## 7. On-chain enforcement (`contract-v3`, local only)

This is a NEAR contract (near-sdk 5.30.1). It re-checks everything with its own `env::ed25519_verify`:
- payments: DAILY only, exact message, epoch, purpose version, allow-list, per-payment and cumulative limits, nonce,
  and buffered release with re-checks;
- the governance matrix (hard-coded and not amendable on-chain): freeze, unfreeze, amend purpose, revoke and rotate;
- recovery: the claim changes nothing; completion needs all survivor consents, the guardian quorum, identity and the
  window;
- more than 50% lost leads to lockdown and reconstitution, which needs a full role set;
- the F-V3-02 override is ported.

It has **no owner, admin, upgrade or withdraw method**. The remaining bypass path is the account's access keys.
`scripts/v3/check-deployment.mjs` checks four invariants:
- D1: no FullAccess key;
- D2: FunctionCall keys only on self, with explicit public methods and never `new`;
- D3: the code hash matches the reviewed build;
- D4: no implicit account.

## 8. Verification levels (honest labels)

| Claim | Level |
|---|---|
| Root, recovery, vault, verifier logic | **Mock / in-process**, deterministic tests (JS) |
| Five-principal OS separation (files, signals, network) | **OS-enforced locally** (`scripts/v3/os-matrix.mjs`, 145 checks; uids, no caps, no_new_privs, the general zone in an empty netns). The V3 services themselves run in-process in the tests; only the privilege matrix is OS-verified |
| On-chain rules | **Contract-verified locally** (near-sdk unit VM, real Ed25519, wasm32 build `b8ca1517…` before F-V3-02, rebuilt after) |
| Real Testnet | **Not done.** NEAR RPC is unreachable from this cloud, there are no funded accounts, and no authorization was given |
| WebAuthn | Real RP verification against a **software authenticator**. No physical authenticator was tested |
