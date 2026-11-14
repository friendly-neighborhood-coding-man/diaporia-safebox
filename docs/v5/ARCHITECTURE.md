# SafeBox V5 architecture

V5 extends V4 (frozen at `705fdbb`, branch `feature/v4-intent-bound-recovery`) without rewriting it. The V5 chain is the V4
genesis plus a V5 genesis extension; every V4 operation still runs through `V4.applyTransition`, and V5 adds its own
commands on top. Everything below is off-chain JavaScript running in one process with logical (not OS) isolation.

```
 owner devices (k1..k5, ORC)          General Zone (AI agent; UNTRUSTED)
   | Command Statements / V4 intents        | requests only
   v                                         v
 +----------------------- Purpose Root (V5 chain) ------------------------+
 | V4 state machine  +  holds registry  +  Rapid-Use  +  delegations      |
 | + incident reviews; every authority-bearing command = Command Statement|
 +-------------------------------+----------------------------------------+
                                 | replicated chain (vault replays it)
 +-------------------------------v----------------------------------------+
 | Execution Vault V5: capability check, 10-min buffer, Risk Policy Engine|
 | decision (signed), bounded ANOMALY_PAYMENT_DELAY, incidents, Rapid-Use  |
 +---------+------------------------+-------------------+-----------------+
           | MOCK ledger            | NotificationService (MOCK transport)|
           v                        v                                     v
     ledger.db             outbox.db -> key holders       Footprint Journal (hash chain,
                                                           witnesses, sealed metadata)
                                                                   |
                                     read-only views: Security Analyst (LLM), reports, verifier
```

## Components (source)

| Component | File | Trust |
|---|---|---|
| V5 chain (holds, Rapid-Use, delegation, incident review, contest) | `src/v5/root/chain.mjs`, `holds.mjs` | trusted (Root) |
| Command Statements | `src/v5/root/command.mjs` | trusted (Root) |
| Owner devices + ORC (simulated) | `src/v5/kit.mjs` | owner side, **simulated** |
| Execution Vault V5 | `src/v5/vault/vault.mjs` | trusted (Vault) |
| Risk Policy Engine (deterministic, signed) | `src/v5/risk/detector.mjs`, `engine.mjs` | trusted service, own key |
| Notification service | `src/v5/notify/notify.mjs` | separate from authorization; MOCK transport |
| Footprint Journal | `src/v5/journal/journal.mjs` | tamper-evident, layer-bound writers |
| Security Analyst | `src/v5/analyst/analyst.mjs` | untrusted model; findings are data |
| Reports | `src/v5/report/report.mjs` | signed counts derived from the journal |
| Independent verifier | `src/v5/supervisor/verifier.mjs` | replays chain + ledger + vault evidence + journal |
| World wiring | `src/v5/world.mjs` | test harness |
| Scenarios, datasets, red team | `src/v5/sim/*`, `src/v5/redteam/*`, `scripts/v5/*` | harness |

## Design rules

1. **Every authority-bearing command is command-bound** (COMMAND-BOUND-AUTHORITY.md). There is no generic "approve" token.
2. **Protection never needs the attacker's cooperation to undo** (PROTECTIVE-HOLD-PROTOCOL.md, ANTI-LOCKOUT.md): a hold is
   a record with issuers; the effective restriction is the union of holds; revoking an issuer drops only the holds that
   depended on it alone.
3. **The only automatic financial reaction is a bounded delay of specific unsettled payments** (ANOMALY-PAYMENT-PROTOCOL.md).
   The engine cannot freeze, revoke, release, approve or change Purpose.
4. **E-mail is notification only** (NOTIFICATION-POLICY.md); it never approves anything.
5. **Rapid-Use removes anomaly delay for an approved scope for at most 24 h**; limits, Purpose and recipients never change
   (RAPID-USE-PROTOCOL.md).
6. **Everything is journaled, and the AI only reads** (FOOTPRINT-JOURNAL.md, SECURITY-ANALYST.md).

## Trust-boundary classification

| Boundary | Status in this evaluation |
|---|---|
| Root / Vault / Engine / Journal / Notify separation | **logical isolation in one process** (separate keys, DirectClient ports, layer-bound writers). Not OS-separated in V5. |
| Owner devices, trusted display, protected confirmation, WebAuthn UV | **SIMULATED** (software authenticator, in-process Ed25519, deterministic renderer). |
| E-mail | **MOCK transport only**; `RealProviderAdapter` reports `NOT_CONNECTED`. No real e-mail was sent. |
| Ledger | **MOCK ledger** (SQLite). No Testnet / Mainnet transaction. |
| On-chain contract | **not extended for V5** (no Rust parity for V5 commands; V4 `contract-v4` unchanged). |
| Security Analyst model | real model calls (Claude Opus 4.8) through a tool-less CLI with a scratch HOME; output only enters through schema intake. |
| Red-team attacker | real model calls (Claude Opus 4.8), General-Zone action surface only. |
