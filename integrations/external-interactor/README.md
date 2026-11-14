# SafeBox External AI Interactor V0 (experimental, MOCK only)

OAuth 2.1-scoped MCP gateway that lets an external AI read SafeBox status, check a payment against policy, and prepare
an immutable **owner-approval request**. It never signs, settles or executes a payment: the owner approves on an
enrolled SafeBox device and the existing V5 Vault verifies that approval against its own Root replica.

Full design, trust boundaries, deployment modes and limitations: [`docs/integrations/EXTERNAL_INTERACTOR.md`](../../docs/integrations/EXTERNAL_INTERACTOR.md).
Pattern mapping from DIAPORIA Agent Commerce PR #9: [`docs/integrations/PAYPAL_PATTERN_MAPPING.md`](../../docs/integrations/PAYPAL_PATTERN_MAPPING.md).

```bash
npm ci
npm run typecheck
npm test               # tsc build + node --test dist/tests/**/*.spec.js (E2E, OAuth, security negatives)
npm run demo           # local MOCK E2E demonstration (loopback only)
npm run serve:mock     # loopback gateway on 127.0.0.1:8791 with an in-process MOCK SafeBox, for manual MCP-host trials
bash scripts/collect-evidence.sh   # reruns everything and writes logs + exit codes to docs/evidence/external-interactor/
```

Layout: `src/` = gateway + adapter (what a deployment would run). `harness/` = MOCK-only world builder, simulated owner
device and test MCP host; never imported by `src/`. Requires Node >= 22.13 (`node:sqlite`) and the repository root
(`src/v5`) next to this package; set `SAFEBOX_REPO_ROOT` to point elsewhere.

Not verified: real MCP hosts (ChatGPT / Claude / Grok), hardware or biometric authentication, OS isolation, NEAR networks.
