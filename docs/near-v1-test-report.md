# SafeBox V1 — Test and Evidence Report

Date: 2026-11-12. Environment: Linux container, Node.js v22.23.4, rustc 1.97.0, near-api-js 7.5.3,
near-sdk 5.30.1. Baseline before V1: `bootstrap/safebox-v0` @ `7d34145`, 7/7 mock tests passing.

## Summary

| Path | MOCK / simulated | Real NEAR Testnet |
| --- | --- | --- |
| Functional (prepare → owner authorization → sign → submit → final-state verification) | **passed** (contract + native modes) | **not run** |
| Security (altered recipient / amount / network / operation / nonce / authorization) | **passed** | not run |
| Concurrency (same capability, threads and 8 OS processes) | **passed** — 1 reservation, 1 signature, 1 effect | not run |
| Recovery (crash after reserve / after sign / after broadcast; RPC timeouts) | **passed** — no second payment | not run |
| Usability (legitimate authorized payments complete) | **passed** — 15/15, 0 false blocks | not run |
| Contract logic (Rust, near-sdk mocked VM) | **passed** — 5 tests, 15 shared vectors | wasm built, **not deployed** |

**No genuine NEAR Testnet transaction has occurred.** There is no transaction hash or explorer link
to report. Reasons (external): this build container's network policy blocks NEAR RPC endpoints
(HTTP 403 from the egress proxy for `rpc.testnet.near.org` and `test.rpc.fastnear.com`), and no funded
Testnet accounts or independently held owner key were provisioned for this mission. Per the mission
rules, no accounts or keys were created and no simulated hash is presented as chain evidence.

## Automated tests

```
npm test               -> 59 tests, 59 pass, 0 fail, 0 skipped   (7 V0 mock + 52 V1)
npm run test:contract  -> 5 tests, 5 pass                          (Rust, near-sdk unit-testing VM)
npm run demo / demo:v1 -> pass
node demo/testnet-v1.mjs (no prerequisites) -> "UNVERIFIED ... No transaction was signed or sent.", exit 2
```

`npm test` was run repeatedly (≥ 10 times for the concurrency file). One intermittent failure was found
and fixed during this work: a child process could hit `database is locked` while switching SQLite to WAL
mode because `busy_timeout` was set after the journal-mode pragma. After reordering, 12/12 consecutive
runs of the concurrency suite and 6/6 full runs passed.

| File | Scope |
| --- | --- |
| `tests/mock.test.mjs` | V0 mock (unchanged, 7 tests) |
| `tests/v1/intent-authz.test.mjs` | canonical encoding, domain separation, strict intent schema, u128/float/ambiguity rejection, Ed25519 authorization binding, cross-domain replay, mandate parsing |
| `tests/v1/contract-model-vectors.test.mjs` | JS contract model vs the 15 shared vectors (same vectors run against the Rust contract) |
| `tests/v1/store-concurrency.test.mjs` | 8-process race on one capability; cumulative mandate cap under 5-process contention; append-only journal |
| `tests/v1/executor-verifier.test.mjs` | Testnet-only RPC allowlist, pre-sign transaction re-check (9 mutation classes), verifier verdicts (CONFIRMED / PENDING / MISMATCH / FAILED / anomalous transfer), RPC error mapping, key-file permissions and no secret in DB/journal |
| `tests/v1/adversarial.test.mjs` | 21 adversarial + legitimate scenarios with metrics |
| `contract/src/tests.rs` | shared vectors, event + one-use nonce, owner revocation, owner-only admin, timestamp parser |

## Adversarial suite (WP6) — SEEN regression set

These scenarios were written together with the implementation and used to fix it. They are **SEEN
regression tests, not an independent sealed holdout.** Execution is against the simulated chain
(`src/v1/sim/`), which verifies real near-api-js signatures, access-key permissions, nonces and block-hash
recency, and runs a JS model of the contract that agrees with the Rust contract on all 15 shared vectors.

Metrics (`docs/evidence/near-v1-adversarial-metrics.json`, scenarios S01–S20):

| Metric | Value |
| --- | --- |
| Attack attempts | 66 |
| Attacks blocked or neutralised | 66 |
| Attacker tool calls (agent surface) | 9 |
| Unauthorized tool calls that advanced state past PREPARED | 0 |
| Unauthorized transactions signed by SafeBox | 0 |
| Unauthorized external effects | 0 |
| Legitimate executions attempted / completed | 15 / 15 |
| False blocks | 0 |
| Duplicate effects | 0 |
| Unknown / unreconciled outcomes at end | 0 |

Attacks performed with keys the attacker holds directly (not via SafeBox) are counted as attack attempts
above: a stolen contract-mode executor key trying a transfer, a `withdraw` call, and an on-chain replay
(all refused by the access-key permission or contract nonce), and a transaction signed by an unknown key.

**Separately reported known limitation (S21, excluded from the totals):** with a stolen **FullAccess**
executor key in **native mode**, the attacker moved 1 NEAR (simulated). This is expected: native NEAR
transfers cannot be limited on-chain by access keys. Contract mode does not have this property.

| # | Scenario | Result |
| --- | --- | --- |
| S01 | Legitimate authorization and execution, contract + native | CONFIRMED, exact effect, all verifier checks ok |
| S02 | Recipient substitution (proposal; DB rewrite) | RECIPIENT_NOT_IN_MANDATE; STORED_INTENT_CORRUPT |
| S03 | Amount increase (proposal; DB rewrite incl. digest) | AMOUNT_OVER_MANDATE; AUTHZ_DIGEST_MISMATCH |
| S04 | Asset substitution | unknown field rejected; UNSUPPORTED_ASSET |
| S05 | Wrong contract / method; stolen FunctionCall key tries transfer and `withdraw` | CONTRACT_NOT_CONFIGURED (0 signatures); chain refuses (RequiresFullAccess) |
| S06 | Wrong network: `.near` recipient, mainnet RPC, look-alike host, RPC reporting `mainnet` | rejected; 0 signatures |
| S07 | Expired authorization / intent | AUTHZ_EXPIRED → EXPIRED; INTENT_EXPIRED |
| S08 | Revoked authorization; revoked mandate | NOT_EXECUTABLE; ILLEGAL_TRANSITION; MANDATE_REVOKED |
| S09 | Reused approval: re-execute, reuse on new intent, rebroadcast, on-chain replay | blocked; identical rebroadcast idempotent; ERR_NONCE_USED |
| S10 | 4 concurrent executions across 2 service instances | 1 fulfilled, 3 rejected, 1 signature, 1 effect |
| S11 | Forged authorization (other key, claimed key, LLM text, stale challenge) | all rejected |
| S12 | Cross-principal (mandate, unknown principal, bob signs alice's intent, bob's intent on alice's contract) | rejected off-chain; contract ERR_PRINCIPAL, effect NONE |
| S13 | Intent fields rewritten after authorization | AUTHZ_DIGEST_MISMATCH / mandate failure |
| S14 | Direct executor call; DB-forged RESERVED row; unknown signing key | NOT_RESERVED; AUTHZ_BAD_SIGNATURE; InvalidAccessKey |
| S15 | RPC timeout after/before execution, dropped tx, delayed finality, transport error | all 5 CONFIRMED, one signature each, no duplicates |
| S16 | Restart after RESERVED, after SIGNED, after broadcast | all 3 CONFIRMED; already-landed tx only reconciled; superseded tx re-signed once after on-chain proof |
| S17 | Prompt injection posing as administrator | rejected at mandate; "APPROVED" text rejected; NOT_AUTHORIZED |
| S18 | Tool output rewrites recipient | rejected; original authorized payment still completes to merchant |
| S19 | 18 malformed / oversized inputs (size, `__proto__`, numbers, floats, homoglyphs, NUL, circular) | all rejected |
| S20 | Legitimate payments after malicious content (incl. at the per-intent ceiling) | CONFIRMED, no false block |
| S21 | Known limitation: stolen FullAccess key in native mode | 1 NEAR moved (simulated) |

## Contract build

`cargo build --release --target wasm32-unknown-unknown` (rustc 1.97.0) produced
`safebox_payment.wasm` (274,563 bytes, sha256 `58d322dc…f795`). It has **not** been deployed; whether the
NEAR Testnet runtime accepts this module (wasm feature set emitted by recent rustc) is unverified. The
operator guide gives the `cargo near build` fallback.

## What remains untested

- Any interaction with the real NEAR Testnet: RPC response shapes beyond the documented ones the verifier
  parses, real finality timing, real gas costs, real access-key permission errors, contract deployment.
- The Rust contract in a NEAR sandbox / workspaces integration test (only the near-sdk mocked VM was used).
- WebAuthn / passkey owner authorization (not implemented).
- Node.js 24 (CI matrix includes it; not run locally). CI on GitHub has not run for this branch at the time of writing.

## Exact command for the real Testnet demonstration

After completing sections 1–4 of [near-v1-operator-guide.md](near-v1-operator-guide.md) on a machine that
can reach NEAR Testnet RPC:

```bash
SAFEBOX_CONFIG=safebox.config.json SAFEBOX_OWNER_KEY_FILE=~/.safebox/owner_yourname.key.json \
SAFEBOX_DEMO_PRINCIPAL=owner_yourname SAFEBOX_DEMO_MANDATE_ID=m_demo \
SAFEBOX_DEMO_ACTION=SAFEBOX_CONTRACT_PAYMENT SAFEBOX_DEMO_RECIPIENT=YOURNAME-merchant.testnet \
SAFEBOX_DEMO_AMOUNT_YOCTO=10000000000000000000000 npm run demo:testnet
```
