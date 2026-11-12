# SafeBox V0 — Architecture Contract (proposed)

## Trust boundaries

- **General session (untrusted):** the LLM may research and propose actions. Chat messages, search results, memory and other agents' claims never grant authority.
- **Intent compiler (trusted service):** validates a typed action and creates a canonical, immutable intent. A hash alone does **not** imply user approval.
- **Independent user authorization (not implemented):** the user reviews the *actual execution parameters* in a trusted non-LLM interface and authenticates separately, bound to the exact intent digest.
- **Capability broker (not implemented):** checks user, mandate, recipient, token, amount, cumulative limit, expiry and one-use state in durable storage.
- **Executor (not implemented):** checks the final payload against the approved intent immediately before signing. Only it may handle real signing material.

## Sessions and handoff

1. First authentication opens a five-minute absolute general session (design target; not implemented).
2. A trusted service prepares and seals the structured action.
3. A distinct second credential (or preferably FIDO2/WebAuthn) confirms the exact transaction outside the LLM interface.
4. Exactly one **already approved** intent may be handed to the executor. A sub-100ms handoff window is an experimental timing target, not a proof of authorization or blockchain confirmation. Security must not rely on timing.
5. The sensitive executor accepts no free-form text and cannot broaden permissions. Execution may complete later without reopening the grant.

## Replay and recovery

Production execution needs an atomic durable state transition, unique operation ID, idempotent submission and reconciliation of UNKNOWN outcomes. Simply consuming an in-memory flag before HTTP execution is insufficient to prove exactly-once external effects.

## Current scaffold: MOCK only

The sample implements strict input shape, a canonical digest, pretend approval, tamper detection and **in-memory** one-use behavior. It does **not** provide real authentication, wallet security, process/network isolation, WebAuthn, a database, chain finality or a real NEAR integration. Treat its methods as attacker-callable. Never connect this mock to funds.
