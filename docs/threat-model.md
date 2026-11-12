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

## V1 update (NEAR Testnet execution)

V1 implements the "Required check" column for the authorization and execution rows; see
[near-v1-security.md](near-v1-security.md) for boundaries and [near-v1-test-report.md](near-v1-test-report.md)
for evidence. Additional attacker capabilities now modelled:

| Attacker capability | Expected outcome in V1 | Test |
| --- | --- | --- |
| Writes arbitrary proposal / context text (prompt injection, fake admin, tool output) | No authority; payee/amount limited by owner-signed mandate; execution still needs owner signature | S17, S18, S19, S20 |
| Submits LLM-written or forged "approval" | Rejected: not a canonical statement, wrong key, wrong challenge, wrong domain | S11 |
| Writes to the SafeBox SQLite database | Cannot forge authority: executor re-verifies owner signature against pinned keys; digest re-derived | S02, S03, S13, S14 |
| Races duplicate executions (threads or OS processes) | One reservation, one signature, one effect | S10, store-concurrency tests |
| Network timeouts / crashes at any lifecycle point | No second payment; reconciliation from chain state | S15, S16 |
| Steals the executor key — **contract mode** | Can only submit owner-signed intents; transfers and other methods refused by access-key permission; replays refused by contract nonce | S05, S09, S14, contract vectors |
| Steals the executor key — **native mode** | **Can move the dedicated account balance** (no on-chain limit) | S21 (known limitation) |
| Points SafeBox at a mainnet or look-alike RPC | Refused before signing | S06 |

Not modelled in V1: compromise of the owner device/key, malicious RPC providers returning forged but
internally consistent tx status (mitigation: query two independent RPC providers), SSRF/egress isolation of
the agent runtime, and side channels.
