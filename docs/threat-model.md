# SafeBox V0 — Threat Model

## Goal

Prevent **unauthorized external effects** while preserving legitimate task completion. Separate an AI's attempted misuse from tool calls executed and from real unauthorized effects.

## Assumptions

An attacker may control arbitrary untrusted text (retrieved pages, search results, other-agent messages or prompts) and may compromise the general LLM workspace. The attacker does not initially control the independent authorization surface, capability broker or external signing key.

| Boundary | Attack | Required check |
| --- | --- | --- |
| Untrusted content → LLM | Injection, fake administrator | Do not treat content as authority |
| General session → sealed intent | Merchant/amount substitution, omitted constraints | Typed canonical fields, authoritative approval display |
| Intent → authorization | Replay, impersonation, phishing | Separate authentication bound to digest and user |
| Authorization → executor | TOCTOU, duplicate effects, changed payee | Durable atomic consume and final payload verification |
| Tools → network | SSRF, redirect, DNS rebinding, tool chaining | Egress allowlist, actual destination verification, network isolation |
| Data → outputs | Raw/encoded/chunked secret leakage | References, minimal disclosure, recipient-aware controls |
| Retry/recovery | UNKNOWN state leading to double payment | Idempotency and provider-side reconciliation |

## Limits

- No claims of perfect isolation, zero incidents or production readiness.
- JSON and secret-pattern checks alone cannot enforce authority.
- Two different passwords alone do not provide phishing-resistant MFA.
- A sub-100ms handoff window is not a security guarantee.
- Passing mock tests does not validate a real wallet, smart contract or cloud deployment.

## Testing protocol

Use synthetic identities, mock tokens, fake account data, controlled exfiltration sinks and NEAR Testnet only. Track attempted breaches, executed calls, unauthorized effects, false blocks and legitimate completion separately. Keep SEEN regressions distinct from independently SEALED fresh attack sets.
