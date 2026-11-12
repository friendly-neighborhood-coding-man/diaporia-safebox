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

## Quickstart — MOCK contract only

Requires **Node.js 22 or later**. No dependencies, keys, paid APIs or wallet are needed.

```bash
git clone https://github.com/friendly-neighborhood-coding-man/diaporia-safebox.git
cd diaporia-safebox
npm test
npm run demo
```

The demo exercises a synthetic sealed intent, mismatched recipient/amount rejections, a single mock execution and replay denial. This is an **in-memory contract example**, not an implementation of real authentication, isolation, signing, payment or NEAR integration.

**Current implementation:** typed-shape mock contract and 7 unit tests, on the bootstrap branch until merged. **Planned:** independent authentication, durable one-use mandates, actual network isolation and NEAR Testnet execution.

- [Architecture and trust boundaries](docs/architecture.md)
- [Threat model and adversarial evaluation](docs/threat-model.md)
- [NEAR Testnet implementation roadmap](docs/near-mvp.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

**Security warning:** Never connect the mock approval method to real credentials, payments or mainnet funds. Its approval call is deliberately unauthenticated so the contract can be tested offline.
