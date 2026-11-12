# SafeBox V1 — Security Boundaries

This is an experimental Testnet prototype. Nothing here is a production guarantee.

## Trust boundaries and what crosses them

| Boundary | Crosses | Enforced by |
| --- | --- | --- |
| Agent / MCP host → SafeBox | `safebox.proposal.v1` JSON only | `parseProposal` exact schema; mandate check; no authority-bearing fields |
| SafeBox → owner | canonical intent + one-time challenge | owner authorizer **recomputes** digest and displays the parameters itself |
| Owner → SafeBox | Ed25519 `safebox.authz.v1` statement | `verifyAuthorization` against owner keys **pinned in operator config** (not DB, not request) |
| SafeBox → executor | intent **id** only | executor reloads record, re-verifies owner signature, rebuilds tx from sealed intent, pre-sign re-check |
| Executor → NEAR | one signed tx | Testnet RPC allowlist + `chain_id == testnet`; access-key permission check; contract checks (contract mode) |
| NEAR → SafeBox | RPC tx status | verifier checks hash, signer, key, nonce, receiver, action, receipts, amount, event, finality |

## Keys

- **Owner authorization key** (Ed25519, `safebox.ownerkey.v1`, file mode 0600): used only by
  `bin/safebox-owner.mjs`. The service and executor see only its public key. It is not a NEAR access key.
  The private part is held in a closure and is never serialised (`toJSON` returns public data only).
- **Executor NEAR key** (near-cli credential JSON, 0600): loaded only by `NearTestnetExecutor`. In
  contract mode it must be a Function-Call key restricted to `execute_payment` on the configured
  contract; the executor refuses to sign otherwise. In native mode it must be FullAccess on a
  **dedicated, minimally funded** Testnet account.
- No key is placed in prompts, logs, journal, database, test fixtures or the repository. Tests generate
  ephemeral keys in memory; `tests/vectors/contract-vectors.json` contains only public keys and signatures.
  A test asserts the executor secret never reaches the SQLite file or journal.

## What is enforced where

| Property | Off-chain (SafeBox) | On-chain (contract mode) |
| --- | --- | --- |
| Owner signature over exact intent | yes | yes (`ed25519_verify` + digest) |
| Recipient / amount / asset / method binding | yes (digest + pre-sign check) | yes |
| Network = testnet | yes (intent, config allowlist, RPC chain_id, account suffix) | yes (`networkId`) |
| Expiry | yes (authorize, reserve, sign) | yes (block time vs intent + authorization expiry) |
| One-use | yes (CAS on SQLite) | yes (intent nonce set) |
| Revocation | yes (owner-signed) | yes (`revoke_nonce`, owner account) |
| Per-payment maximum | mandate | `max_payment_yocto` |
| Cumulative limit, recipient allow-list | mandate (atomic reservation) | **no** |
| Caller restriction | — | only `executor_id` |

In **native mode nothing is enforced on-chain**: a FullAccess key can move the account's entire balance.
Isolation and limits there rely on SafeBox code, key custody and keeping the account balance small. This is
demonstrated deliberately by adversarial scenario S21. Use contract mode when on-chain limits matter.

## Explicit non-claims / known limitations

1. **No live Testnet evidence yet.** All execution results so far come from the simulated chain.
2. The owner authorizer is a CLI on the operator's machine. It is a real cryptographic boundary only
   if the owner key file is kept away from the AI runtime (separate OS user or separate device).
   WebAuthn/passkey authorization is not implemented in V1.
3. The display shown by the owner authorizer is trusted only as much as the machine it runs on.
4. Same-host compromise of the SafeBox service process (not just its DB) could submit owner-signed
   intents early or not at all, but cannot forge owner signatures; in native mode it could also misuse
   the FullAccess key.
5. Cumulative mandate limits are off-chain. A compromised service could exceed them up to the contract's
   per-payment maximum × number of owner-signed intents.
6. Native-mode expiry is enforced only before signing; a signed native tx may still land later within
   NEAR's transaction validity window (~1 day of blocks).
7. `UNKNOWN` resolution for old transactions requires an archival RPC; SafeBox leaves them `UNKNOWN`
   rather than guessing. A durable "fence" transaction to retire an in-flight nonce is not implemented.
8. The local nonce allocator assumes one active executor process per key; concurrent executors could
   collide on a nonce (safe — one tx is rejected and reconciled — but may need re-authorization in native mode).
9. The SQLite journal hash chain has no external anchor; an attacker with full disk access could rewrite it.
10. The Rust contract has unit tests (near-sdk mocked VM) and shared vectors but no sandbox/integration
    test and no external audit; its compiled wasm has not been deployed.
11. The adversarial suite is a SEEN regression set written alongside the code, not a sealed holdout.
