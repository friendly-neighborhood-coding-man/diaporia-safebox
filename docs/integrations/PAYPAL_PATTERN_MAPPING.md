# DIAPORIA Agent Commerce (PR #9) → SafeBox External Interactor: pattern mapping

Reference: `friendly-neighborhood-coding-man/diaporia-agent-commerce`, branch `integration/mvp-full-layer` at `759bd37`
(Draft PR #9). Only interoperability patterns were adopted. Nothing from the PayPal execution path was imported.

| PR #9 source | What it does there | SafeBox V0 | Decision |
|---|---|---|---|
| `src/mcp/MCPCommerceAdapter.ts` | Per-request `McpServer` bound to one principal; tools registered only when the token has the scope; `structuredContent` + output schemas; annotations; `_meta` effect labels | `src/mcp/server.ts`: same per-request/per-principal model, scope + deployment-mode filtered registration, strict input objects, output schemas parsed server-side, `safebox/effect` labels | **Adopted** |
| `src/auth/oauth.ts` | OAuth 2.1 AS + RS: RFC 9728/8414/7591/8707/7009/9207, PKCE S256, refresh rotation, code replay revocation | `src/auth/oauth.ts`: same flow on `node:sqlite`; tokens additionally bound to the SafeBox account at consent; scope set `safebox.*`; 15-min access tokens | **Adopted** (adapted) |
| Owner-key login on consent page | Development stand-in for an IdP | `src/auth/accounts.ts`: same status, explicitly a placeholder; cannot approve anything | **Adopted as placeholder only** |
| `src/http/server.ts` `/mcp` | Stateless Streamable HTTP, DNS-rebinding protection, host/origin allow lists, 401 + `WWW-Authenticate`, rate limiter | `src/http/app.ts`: same, plus 16 KiB body cap and JSON depth cap ≤ 10 | **Adopted** |
| Payment tools only on loopback; public OAuth = read only | Deployment restriction | `src/mode.ts`: `mock-loopback` vs `public-readonly`; no flag widens public mode | **Adopted** |
| `tests/oauth.test.ts`, `tests/mcp-e2e.test.ts` | SDK `OAuthClientProvider` interop, negative OAuth cases, host E2E | `tests/oauth.spec.ts`, `tests/e2e.spec.ts`, `tests/security.spec.ts` | **Adopted** (pattern) |
| `docs/REMOTE_MCP_AUTH.md`, `docs/MCP_TOOLS.md` | Docs of auth + tools | `docs/integrations/EXTERNAL_INTERACTOR.md` | **Adopted** (pattern) |
| PayPal client, credentials, order capture, webhooks | Real/Sandbox payment execution | none | **Prohibited**: SafeBox settles only through its own Vault/Mock Ledger |
| Purchase mandates, buyer approval on PayPal | Spending authority model | none. Authority = enrolled-device WebAuthn assertion over the exact capability, verified by the Vault | **Prohibited** |
| Research/compare, external browsing, browser checkout handoff | Shopping research and merchant-site carts | none: no network fetch, URL, file path, shell or code execution tool exists | **Prohibited** |
| Merchant order state, fulfillment | Order lifecycle | none | **Prohibited** |
| Owner review page / cancel routes on the same HTTP server | Owner web routes next to `/mcp` | none: the gateway has no owner/approval route in any mode; owner approval is on the device | **Not adopted** (stricter) |
