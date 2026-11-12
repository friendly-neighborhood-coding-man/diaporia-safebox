# SafeBox V1 — NEAR Testnet Execution Architecture

Status: **implemented and tested offline; live NEAR Testnet run not yet performed** (see
[near-v1-test-report.md](near-v1-test-report.md)). The V0 MOCK contract in `src/mock/` is unchanged.

## Separation of stages

| Stage | Component | Who controls it | Output |
| --- | --- | --- | --- |
| Request understood | Upstream agent (DIAPORIA Buy, any agent, MCP host) | untrusted | `safebox.proposal.v1` |
| Action judged appropriate | `SafeBoxService.propose` + owner-signed **mandate** | deterministic code, owner-signed policy | `PREPARED` sealed intent + one-time challenge |
| Action independently authorized | `bin/safebox-owner.mjs` (owner authorizer, separate process) | owner's Ed25519 key | `safebox.authz.v1` statement + signature |
| Action executes | `NearTestnetExecutor` | executor key (NEAR access key) | one signed NEAR transaction |
| Effect verified | `verifyTxOutcome` + `SafeBoxService.reconcile` | NEAR RPC evidence | `CONFIRMED` / `FAILED` / `UNKNOWN` with evidence |

An agent's decision is never execution authority: the agent tool surface (`createAgentTools`) has
only `safebox_propose_payment`, `safebox_get_status` and `safebox_request_execution`. There is no
tool that authorizes, mints a mandate, touches a key, edits an intent, or signs raw transactions.
`request_execution` can only advance an intent that the owner has already signed.

## Components (all under `src/v1/`)

- `canonical.mjs` — canonical JSON (sorted keys; string or string-array values only; printable ASCII),
  domain-separated SHA-256 (`DIAPORIA_SAFEBOX_{INTENT,AUTHZ,REVOKE,MANDATE}_V1\n`), strict validators
  (u128 decimal-string amounts, ISO-8601 ms timestamps, NEAR account ids, **testnet-only** accounts).
- `intent.mjs` — `safebox.intent.v1` (WP1). Two actions:
  - `SAFEBOX_CONTRACT_PAYMENT` (recommended): tx = `FunctionCall(execute_payment, args, 30 Tgas, 0 deposit)`
    to the SafeBox payment contract, which releases the exact amount to the exact recipient.
  - `NEAR_NATIVE_TRANSFER`: tx = one `Transfer(amount)` from a dedicated executor account.
  Every execution field is explicit and bound: version, intent id, principal, mandate, chain `near`,
  network `testnet`, action, signer account, tx receiver, recipient, asset `NEAR`, amount (yocto),
  method / gas / deposit (contract mode), 128-bit one-use nonce, created/expiry (TTL ≤ 30 min).
- `authz.mjs` — Ed25519 statements (WP2): authorization (bound to intent id, digest, principal,
  pinned owner key, server challenge, issue/expiry ≤ 15 min and ≤ intent expiry), revocation, mandate.
- `store.mjs` — SQLite broker (WP3): WAL + `synchronous=FULL`; every transition is a compare-and-set
  inside `BEGIN IMMEDIATE`, with an append-only (trigger-enforced), hash-chained journal row in the same
  transaction; mandate spend is reserved atomically with the `AUTHORIZED → RESERVED` transition.
- `near/executor.mjs` — WP4. Accepts only an intent id; reloads the sealed record, re-verifies the owner
  signature against **pinned** owner keys, checks RPC `chain_id == testnet`, checks the executor
  access-key permission, allocates a nonce durably, builds the transaction from the sealed intent only,
  decodes the encoded bytes and re-checks every field (`verifyEncodedTransaction`), signs with
  near-api-js `KeyPairSigner`, and re-checks the signed bytes and hash.
- `near/rpc.mjs` — raw JSON-RPC (`status`, `query`, `block`, `send_tx`, `EXPERIMENTAL_tx_status`) with
  explicit timeouts and `redirect: 'error'`; `near/config.mjs` — exact-origin Testnet RPC allowlist.
- `near/verifier.mjs` — WP5. Derives the verdict from `EXPERIMENTAL_tx_status` (tx + receipts), never from
  `send_tx` success.
- `service.mjs` — orchestration, reconciliation and crash recovery.
- `proposal.mjs` — upstream interface (see below). `runtime.mjs` — builds the service from operator config.
- `sim/` — **simulation only**: `SimulatedNearTestnet` (verifies real signatures/nonces/permissions and
  answers in RPC shape) and a JS model of the contract. Evidence from it is labelled `simulated: true`
  with `explorerUrl: null` so it can never be mistaken for chain evidence.
- `contract/` — Rust `safebox-payment` contract (near-sdk 5.30.1).

## Lifecycle

```
PREPARED ──owner sig──▶ AUTHORIZED ──atomic reserve──▶ RESERVED ──sign + persist──▶ SIGNED ──send_tx──▶ SUBMITTED ──verify──▶ CONFIRMED
   │                       │                             │                            │  ╲                 │                    ╲▶ FAILED (effect NONE, proven)
   ├▶ EXPIRED / REVOKED    ├▶ EXPIRED / REVOKED          └▶ FAILED (pre-sign check)   │   ╲▶ UNKNOWN ◀─────┘
   └▶ REJECTED                                                                        └─(proof: never includable, contract mode)─▶ RESERVED (re-sign)
```

- **Authorization consumption is exactly-once** (`AUTHORIZED → RESERVED` CAS). This is distinct from
  the **external effect**, which is established only from chain evidence.
- A transaction is broadcast only after its signed bytes and hash are durably stored (`SIGNED`).
- `UNKNOWN` is never blindly retried. Reconciliation queries the transaction by hash. If the node does
  not know it, SafeBox may **re-broadcast the identical signed bytes** (same hash and nonce, idempotent).
  It re-signs only after proving the old transaction can never be included (access-key nonce already
  ≥ its nonce) **and** the contract reports the intent nonce unused, so even a mistaken inference cannot
  pay twice (the contract consumes the intent nonce). Native mode never re-signs automatically.
- Recovery (`service.recover()`): `RESERVED` without a stored tx → sign (nothing was ever sent);
  `SIGNED/SUBMITTED/UNKNOWN` → reconcile.

## Contract-mediated payment (why it is the recommended mode)

NEAR Function-Call access keys restrict *which contract and methods* a key may call, but cannot carry
value and their allowance is a **gas** allowance, not a spending cap. So the executor gets a
Function-Call key limited to `safebox-pay.testnet::execute_payment`, and the contract enforces, on-chain:
owner Ed25519 signature (via `env::ed25519_verify`) over the authorization statement, SHA-256 binding of
the exact intent bytes, `principalId`, `networkId == testnet`, action/method/asset, this contract as
receiver, the configured executor as caller, expiry against block time, one-use intent nonce, owner
revocation (`revoke_nonce`) and a per-payment maximum. A stolen executor key can therefore only submit
payments the owner already signed. Cumulative limits and recipient allow-lists remain off-chain (mandate).

## Upstream integration contract (`safebox.proposal.v1`)

```json
{ "v": "safebox.proposal.v1", "principalId": "owner_alice", "mandateId": "m_alice",
  "action": "SAFEBOX_CONTRACT_PAYMENT", "recipientId": "merchant.testnet",
  "amountYocto": "1000000000000000000000000", "ttlSeconds": "600",
  "context": { "source": "diaporia-buy", "summary": "≤500 printable chars", "evidenceRefs": ["≤10 refs"] } }
```

Exact field set (unknown fields rejected, ≤ 8 KiB). The proposer cannot set signer, contract, method,
gas, deposit, nonce, timestamps, asset or any authorization. `context` is stored for audit only and never
influences execution. SafeBox is host-neutral and does not depend on DIAPORIA Buy or on any of its
research parser behaviour (in particular not on the provisional K3 category schema).
