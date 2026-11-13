# SafeBox V2 — Independent Sensitive Zone: Architecture, Threat Model, Invariants, IPC Contract

Status: experimental **mock** milestone. Synthetic keys, synthetic identities, Mock NEAR Ledger only. No real
NEAR transaction, no Testnet or Mainnet access, no V1 key or contract is touched by any V2 code path.

## 1. Research question and principle

> Can an autonomous AI operate within an independently secured financial execution system without degrading its
> security, even when the AI's general execution environment is compromised?

Principle: the financial execution system must be secure **without** AI. In V2 an AI (or anything in the General
Zone) can only *propose*; spending authority exists only as owner-signed statements verified against keys pinned in
root-owned configuration, and only the Sensitive Zone holds the executor key.

## 2. Security domains (OS principals)

| Domain | OS principal (uid) | Holds | Can reach |
| --- | --- | --- | --- |
| GENERAL ZONE (assumed fully compromised): agent adapter, attack injector, untrusted tool/web content | `sbx2-gen`, in an **empty network namespace** | its own scratch dir | `gz.sock` (Sensitive Zone public API), `task.sock` (controller work queue) |
| SENSITIVE ZONE: policy decision point, capability verification, reservations, buffer, mock executor | `sbx2-sens` | executor private key (synthetic), sensitive DB (0700) | `ledger exec.sock` |
| MOCK LEDGER (plays the chain) | `sbx2-ledger` | ledger DB (0700) | — (serves exec/read/admin sockets) |
| INDEPENDENT SUPERVISOR: watchdog, verifier, controller, owner authority simulation | `sbx2-sup` | owner private keys (synthetic), ground-truth labels, freeze log, owner issuance log, virtual clock (writer) | `ctl.sock`, `ledger read.sock`, `ledger admin.sock`, `gz.sock` |
| Root launcher (TCB) | root | nothing secret: it never reads private keys | creates principals/ACLs, pins public keys into root-owned config |

Every zone process runs with `setpriv --no-new-privs --inh-caps=-all --bounding-set=-all` and an explicit supplementary
group list. Sockets live in per-socket directories whose owner/group/mode (`2750`, socket `0660`) are the access
policy; the kernel performs caller authentication (workload identity by filesystem ACL, SPIFFE-style attestation by
uid/gid rather than by bearer secret). Source code and the Node runtime are root-owned and not writable by any zone.

```
             task.sock (sbx2-gtask)                       gz.sock (sbx2-gzipc)
  SUPERVISOR ───────────────────────▶ GENERAL (netns: none) ───────────────▶ SENSITIVE ──exec.sock (sbx2-lexec)──▶ LEDGER
     │  ctl.sock (sbx2-ctl) ─────────────────────────────────────────────────────▲                                   ▲
     └── read.sock (sbx2-lread), admin.sock (sbx2-ladmin) ───────────────────────────────────────────────────────────┘
```

## 3. Authority model (what "authorized" means)

1. **Owner policy** (`safebox.v2.policy`, Ed25519, owner key): allow-listed recipients, asset, per-payment max,
   cumulative max, max pending reservations, max pending exposure, max executions, buffer length (>= 10 min floor
   in trusted config), max capability TTL, validity window (= maximum experiment duration). Loaded only through the
   supervisor control channel; re-verified from stored signed bytes on every use.
2. **Owner task capability** (`safebox.v2.cap`): one per owner-intended payment — exact recipient, max amount,
   policy id, validity window, single use. Issued by the owner (supervisor) and handed to the agent with the task.
   The capability, not the agent's text, is the authority.
3. Proposal (`PROPOSE`): capability + recipient + amount + asset + untrusted memo. The deterministic policy decision
   point (`src/v2/sensitive/policy.mjs`, OPA-style pure function) allows only if *every* rule passes.

An effect on the Mock Ledger is **authorized** iff the independent verifier can match it to an owner-issued
capability (recipient equal, amount <= cap, asset NEAR, inside policy limits, not revoked, not expired, first and only
effect for that capability, not earlier than issuance + buffer, not during a freeze). Everything else is unauthorized,
including transfers to allow-listed merchants that no capability authorized.

## 4. Payment lifecycle

`PROPOSED → AUTHORIZED → RESERVED → BUFFERED → RELEASED → SETTLED`; alternatives `REJECTED` (decision log),
`FROZEN`, `CANCELLED`, `EXPIRED`, `FAILED`, `UNKNOWN`. Proposal→Buffered is one SQLite transaction (journal row per
step). At `release_at` the Sensitive Zone re-checks authoritative state (freeze level, fresh watchdog lease,
unchanged policy digest, policy window, revocation, capability expiry, execution count), allocates a key nonce,
signs the ledger transfer and makes the signed bytes durable **before** submitting. Recovery only re-submits those
exact bytes (ledger is idempotent on tx id and one-use intent nonce); a new signature is produced only after the
ledger proves the old bytes can never be accepted (stale key nonce), still with the same payment id + intent nonce.

## 5. Security invariants (checked by tests and by the independent verifier)

| Id | Invariant | Enforced by | Independently checked by |
| --- | --- | --- | --- |
| INV-AUTH-0 | every ledger effect has an owner capability | Sensitive policy (signature with pinned key) | verifier `NO_OWNER_CAPABILITY` |
| INV-AUTH-1/2/3 | recipient = capability recipient and allow-listed; amount <= capability and policy max; asset NEAR | policy rules | verifier codes |
| INV-ONCE-1 | at most one effect per capability / payment | `caps_used` PK + ledger unique intent nonce/payment id | verifier `DUPLICATE_EFFECT_*` |
| INV-BUF-1 | no effect before buffer elapsed | `release_at`, release re-check, clock writable only by supervisor | verifier `BUFFER_BYPASSED` (issuance + buffer lower bound) |
| INV-FREEZE-1 | no new effect after a confirmed freeze | Sensitive freeze level + ledger freeze (ledger frozen first) | verifier `EFFECT_DURING_FREEZE` (ledger sequence at freeze) |
| INV-FREEZE-2 | unfreeze needs operator signature bound to this freeze; frozen payments are cancelled, never auto-released; unauthorized PENDING transfers are voided first (BR-001) | `UNFREEZE` statement check, recovery gates | recovery checks |
| INV-BUDGET | per-payment, cumulative, pending count/exposure, executions, duration | policy rules in the Sensitive Zone; ledger per-transfer cap | verifier cumulative/execution checks |
| INV-KEY | no zone except the Sensitive Zone can read the executor key; only the supervisor holds owner keys | uid + 0700 dirs + no_new_privs | access matrix + exfiltration attacks |
| INV-AUDIT | no state change without a hash-chained audit row (same transaction) | SQLite transaction | watchdog journal-chain check |
| INV-FAILCLOSED | missing policy/lease/clock/audit ⇒ no release | release re-check, lease, clock reader | drills |

## 6. Minimal IPC contract (deny by default)

Newline-delimited JSON, frame <= 16 KiB, envelope exactly `{op, args, rid}`, op from a closed table, exact argument
field sets, string-only values except `signed` objects `{statement, signature}`; unknown op → `OP_DENIED`.

* `gz.sock` (General Zone): `PROPOSE{capability,recipientId,amountYocto,asset,memo}`, `STATUS{paymentId}`, `HEALTH{}`.
  No signing, release, policy, freeze, clock or key operation exists on this socket.
* `ctl.sock` (supervisor only): `LOAD_POLICY`, `REVOKE_CAP`, `HEARTBEAT`, `HOLD`, `FREEZE`, `CLEAR_HOLD`,
  `UNFREEZE{operator-signed}`, `TICK`, `STATE`, `PAYMENTS`, `JOURNAL`, `DECISIONS`.
* ledger `exec.sock` (Sensitive only): `SUBMIT_TX{executor-signed}`, `TX_STATUS`. `read.sock`: `TRANSFERS`, `BALANCES`,
  `TX_STATUS`, `STATE`, `REJECTS`. `admin.sock`: `FREEZE`, `UNFREEZE{operator-signed}`, `SETTLE_DUE`, `VOID_PENDING` (frozen + PENDING only).

## 7. Supervisor: watchdog, freeze, recovery

* Watchdog scans (own 500 ms loop + after every controller tick): ledger effects through the independent verifier,
  ledger and Sensitive journal chains, freeze-state consistency, stuck `UNKNOWN` payments, and a **pre-release audit**
  of every buffered payment against the owner issuance log (uses the buffer to stop a policy-bypass before any effect).
* Classification: `CONFIRMED_BREACH` ⇒ FREEZE (ledger first, then Sensitive; persisted in the supervisor's freeze log
  and re-applied after any restart); `UNCONFIRMED_ANOMALY` ⇒ HOLD (no releases) until a clean review clears it.
* Heartbeat lease: releases require a watchdog heartbeat within `leaseMs` (wall clock); killing or stalling the
  watchdog therefore stops releases (fail closed). The General Zone cannot signal the watchdog (EPERM).
* Failure-repair workflow (`repairWorkflow`): DETECT → DIAGNOSE (violated invariants from verifier codes, culprit
  event) → PATCH → REPLAY exact malicious requests → MUTATIONS (same technique, fresh owner capability) → REGRESSION
  (full test suite) → VERIFY (recovery checks, unauthorized PENDING voided) → RESUME only if all gates pass. A denial
  counts only if it carries a reason other than `FREEZE_ACTIVE`/`CAPABILITY_ALREADY_USED`.

## 8. Reference architectures (principles reused, systems not embedded)

| Reference | Principle | V2 realisation |
| --- | --- | --- |
| OpenBao | auth + policy before any operation; barrier; seal; transit signing without key export; audit; fail closed | executor key never leaves the Sensitive Zone and is only used at release; no export/sign op; hash-chained audit in the same transaction as every state change; FREEZE ≈ seal; HOLD/lease fail closed |
| OPA | deterministic policy, separated from application, explicit decisions | `evaluatePayment`/`evaluateRelease` pure functions over explicit facts; all deny reasons returned and logged |
| SPIRE | workload identity, trusted service boundaries | caller identity = kernel-checked uid/gid on socket directories; no bearer tokens (a stolen synthetic token grants nothing) |

## 9. Enforced vs simulated

| Property | Status |
| --- | --- |
| Separate OS principals, 0700 key dirs, socket ACLs, no_new_privs, no capabilities, General Zone network namespace | **Enforced by the Linux kernel** in the OS-isolated deployment (`scripts/v2/run-isolated.mjs`) and verified by an access matrix with positive controls |
| Ed25519 signatures (owner, operator, executor), canonical encoding, domain separation | Enforced (real crypto, synthetic keys) |
| Payment ledger, balances, settlement, finality | **Simulated** (Mock NEAR Ledger; plays the chain, enforces executor signature, nonces, per-tx cap, freeze) |
| Owner / human approval | **Simulated** (owner simulator in the supervisor signs capabilities for controller-defined owner-intended tasks) |
| AI agent | **Deterministic mock** (deliberately gullible: obeys injected directives and permission claims). No real model was executed; no real-model security claim is made |
| Clock | Virtual clock file written only by the supervisor; real wall clock only for the watchdog lease |
| In-process mode (`src/v2/world.mjs`, most unit tests) | Logical boundaries only — OS isolation NOT exercised there |
| Root, kernel, Node runtime, launcher | Trusted computing base (not attacked) |
