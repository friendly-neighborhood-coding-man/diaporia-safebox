# NEAR Testnet MVP — Work Plan

**Status (V1, branch `feature/near-testnet-v1`):** work packages 1–8 are implemented and tested offline against a simulated chain; a live Testnet transaction has not yet been executed. See [near-v1-test-report.md](near-v1-test-report.md). The V0 mock below remains unchanged.

## Target demonstration

An approved fixed-purpose testnet transaction succeeds; altered recipient, amount, expiry, replay and direct executor calls fail **before signing**. Show a real testnet transaction hash and independently verified final state only when a genuine network transaction exists.

## Work packages

1. Canonical transactions with integer atomic amounts stored as strings (no floating point for money).
2. Independent user authentication, ideally WebAuthn, with a server-side challenge linked to the sealed intent.
3. Durable mandate state with atomic single-use claims, replay checks and concurrency tests.
4. Testnet-only signing/execution adapter; never expose full-access NEAR credentials to the LLM.
5. Where Function-Call Access Keys are used, restrict contract and methods; separately enforce recipient/asset/amount. NEAR access-key allowance is a **gas** allowance, not a monetary spending cap.
6. Idempotent retries and reconciliation for UNKNOWN results; no blind repeat transfers.
7. Synthetic injection, impersonation, SSRF, substitution and tool-result attack tests.
8. A reproducible demo, truthful status output and a verified testnet explorer link.

## Before testnet signing

Do not pass seed phrases or keys through agent prompts or logs. The general session must not be able to call the signing API directly. The actual signed payload must match the exact reviewed intent. No mainnet deployments in this hackathon prototype.
