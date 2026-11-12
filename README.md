# DIAPORIA SafeBox

**Autonomy without unrestricted authority.**

DIAPORIA SafeBox is an experimental capability-security architecture for autonomous AI agents.

It explores a simple question:

**Can an AI agent remain useful even when its instructions are compromised, without gaining the ability to perform unauthorized actions?**

SafeBox separates intelligent decision-making from sensitive execution.

## Core Architecture

**1. General Session**

An AI agent explores, plans, and prepares actions within a restricted workspace.

**2. Sealed Intent**

Sensitive actions are converted into structured, immutable execution requests, binding the intended operation, recipient, amount, and authorization scope.

**3. Independent Authorization**

The user authenticates through a separate interface. The sensitive execution environment does not accept free-form agent instructions.

**4. Capability Enforcement**

A deterministic execution layer checks the sealed intent against the authorization policy. Permissions are constrained to specific actions and designed to be single-use.

**5. Verified Execution**

Authorized operations are executed through a restricted external interface, with independently verifiable results.

## NEAR Integration

The initial implementation targets NEAR Testnet and explores policy-enforced economic actions by AI agents.

The intended demonstration includes authorized testnet transactions and simulated adversarial attempts to modify transaction details, exceed delegated authority, or reuse approvals.

## Adversarial Research

SafeBox is designed to support controlled experiments involving:

- Prompt injection and administrator impersonation
- Unauthorized capability use
- Transaction and recipient substitution
- Replay and duplicate-execution attempts
- SSRF and unauthorized network access
- Synthetic credential and data exfiltration
- Cross-agent authority confusion

Experiments use synthetic data, isolated services, and mock or testnet transactions.

## Relationship to DIAPORIA Buy

SafeBox builds on the capability and purchase-authorization concepts explored in [DIAPORIA Buy](https://github.com/friendly-neighborhood-coding-man/diaporia-agent-commerce).

DIAPORIA Buy focuses on research, product selection, and purchasing workflows.

SafeBox focuses on independently enforcing the authority under which sensitive actions may execute.

## Project Status

**Experimental prototype — under development.**

The architecture describes intended functionality, not a completed security guarantee. Security properties will be evaluated through reproducible adversarial tests and independently checked execution outcomes.

This project is not intended for production financial transactions in its current state.

## NEAR Hackathon 2026

**Primary track:** Agent Economy  
**Additional track:** AI Security & Defense

The NEAR integration is the project's first implementation target.

*Let AI explore freely. Let only authorized actions execute.*

---

## Quickstart

Requires **Node.js 22.13 or later** (uses the built-in `node:sqlite`). Offline tests need no keys, wallet, network or funds.

```bash
git clone https://github.com/friendly-neighborhood-coding-man/diaporia-safebox.git
cd diaporia-safebox
npm ci
npm test               # V0 mock + V1 tests (V1 runs against a SIMULATED NEAR testnet)
npm run demo           # V0 in-memory mock (unchanged)
npm run demo:v1        # V1 end-to-end: proposal -> owner Ed25519 authorization -> signed NEAR tx -> verification (simulated chain)
npm run test:contract  # Rust payment contract tests (Rust >= 1.95)
```

### V1 — NEAR Testnet execution (experimental)

- **Sealed intent** `safebox.intent.v1`: canonical, domain-separated, every execution field bound (testnet only).
- **Independent authorization**: the owner signs the exact intent digest with an Ed25519 key held only by
  `bin/safebox-owner.mjs`; SafeBox verifies it against a pinned public key. Agents cannot authorize.
- **Durable capability broker**: SQLite compare-and-set lifecycle, single-use reservation, owner-signed
  mandates, hash-chained append-only journal, crash recovery and UNKNOWN reconciliation.
- **NEAR executor**: near-api-js transaction built only from the sealed record and re-checked before signing.
- **Payment contract** (`contract/`): releases funds only for owner-signed, unexpired, one-use intents.
- **Independent verification** from NEAR RPC transaction status, not from submission success.

**Status: no live NEAR Testnet transaction has been executed yet.** All V1 execution evidence so far is
from the simulated chain. The Testnet run needs operator-created Testnet accounts and keys:
see the [operator guide](docs/near-v1-operator-guide.md) (`npm run demo:testnet`).

- [V1 architecture](docs/near-v1-architecture.md) · [V1 security boundaries](docs/near-v1-security.md) ·
  [V1 test report](docs/near-v1-test-report.md) · [V1 operator guide](docs/near-v1-operator-guide.md)
- [V0 architecture and trust boundaries](docs/architecture.md) · [Threat model](docs/threat-model.md) ·
  [NEAR roadmap](docs/near-mvp.md) · [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md)

**Security warning:** experimental Testnet prototype. Never use mainnet accounts or real funds. The V0 mock
approval method is deliberately unauthenticated; never connect it to anything real.
