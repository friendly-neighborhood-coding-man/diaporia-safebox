# SafeBox External AI Interactor V0

Status: **experimental, MOCK only, Draft PR, never merge.** Spec: issue #8. Code: `integrations/external-interactor/`.
Base: frozen V5 `93816b5` (PR #7); also verified combined with V5.1 `6586a14` (PR #10), see
`docs/evidence/external-interactor/combined-v51-6586a14/`. No file under `src/`, `tests/`, `scripts/` or the root `package.json` is modified.

## What it is

An MCP server that lets an external AI assistant (ChatGPT, Claude, Grok or any MCP client) work with a SafeBox account
without ever holding payment authority:

| Tool | Scope | Effect |
|---|---|---|
| `get_safebox_status` | `safebox.status.read` | Read. Freeze/lockdown, number of active holds by scope kind, Rapid-Use active, Purpose limits, remaining daily limit, settlement buffer, pending approval requests. Redacted. |
| `check_payment` | `safebox.payment.check` | Read. Purpose violations + blockers (freeze, merchant hold, open case, all payment credentials held), fee (MOCK: 0) and buffer. `isAuthorization: false`. |
| `prepare_payment` | `safebox.payment.prepare` | Creates one immutable, expiring (15 min) **approval request**. Never signs, never proposes to the Vault, no ledger effect. Idempotent per `(account, client, idempotencyKey)`. |
| `get_payment_status` | `safebox.payment.read` | Read. Request state; after owner approval the Vault payment state and the MOCK ledger receipt. `settledVerified` is true only when Vault `SETTLED`, ledger `SETTLED` and the receipt's recipient/amount/paymentId match the request. |

## Trust boundaries

```
External AI host ──OAuth 2.1 bearer──▶ MCP gateway (src/http, src/mcp)          ── holds: OAuth DB, rate limiters
                                         │ only object received: AiPort (4 frozen closures)
                                         ▼
                                   SafeBox service adapter (src/safebox)         ── holds: approval-request table
                                         │ GZ client (PROPOSE/STATUS/HEALTH/ROOT_VIEW), read-only ledger, read-only vault views
                                         ▼
Owner's enrolled device ─OwnerPort─▶ adapter ─PROPOSE──▶ V5 Execution Vault (own Root replica) ─▶ buffer ─▶ Mock Ledger
   (V0: simulated V5 devices,                         (verifies capability + WebAuthn UV, epoch, Purpose,
    harness only)                                       credential status, holds, limits, anomaly delay, Rapid-Use)
```

- The account is taken from the verified token (bound at consent), never from arguments. Tool inputs are strict
  (`z.strictObject`): any extra field such as `accountRef`, `accountId` or `approval` is refused.
- The gateway gets **only** the `AiPort`. It has no reference to the owner world, any signer, the Root admin socket or the
  Vault control socket. A test walks the compiled gateway sources and fails if they mention the V5 world/kit, paycap
  signing, `signDigest`, `child_process` or `eval`.
- The `OwnerPort` (read pending request, decline, submit device-signed capability, crash recovery) is not reachable over
  HTTP or MCP in any mode. It grants nothing by itself: the Vault verifies the enrolled-device assertion over the exact
  capability against its own Root replica.

## Owner approval handoff (one use, exact, command-bound)

1. `prepare_payment` stores `{requestId, account, recipient, amountYocto, NEAR, sanitized memo, purposeId, purposeVersion,
   epoch, chainId, vault account, createdAt, expiresAt}` and `requestDigest = SHA-256("DIAPORIA_SAFEBOX_EXTERNAL_INTERACTOR_APPROVAL_REQUEST_V0\n" || V3 canonical(fields))`.
2. The device app reads the request through the OwnerPort, **recomputes the digest**, compares epoch / Purpose / chain /
   recipient against its OWN verified Root view, and displays the payment from SafeBox state. The AI's memo is shown
   labelled `UNTRUSTED, not an instruction`.
3. The human decides. Only then the enrolled DAILY passkey signs the V3/V5 payment capability (WebAuthn assertion with
   UV, challenge = capability digest) with `taskRef = "mcp-" + requestDigest[0..48]`, binding the signature to this request.
4. The adapter checks exactness (recipient, amount, asset, operation, account/chain, epoch, Purpose, taskRef), moves the
   request `AWAITING_OWNER_APPROVAL → OWNER_SUBMITTING` with a conditional update (one use), and forwards it to the Vault
   General-Zone `PROPOSE`. The existing V5 code does everything else: capability verification, single-use cap ids,
   minimum 600 s buffer, release-time re-check, holds, anomaly delay, Rapid-Use, limits, journal.
5. Crash recovery: a request left in `OWNER_SUBMITTING` (and not in flight in this process) is resolved from the Vault's
   own `caps_used` index. If the Vault has no record of the capability, the request is closed as `NOT_RECEIVED_BY_VAULT`;
   nothing is re-signed or re-sent. Because another process's PROPOSE may still have been in flight, a late Vault
   acceptance always wins: `finishSubmit` and every later read reconcile the record to the Vault payment (the Vault is
   authoritative). Every state update checks that exactly one row changed, otherwise `STATE_CONFLICT`.

## Deployment modes

| Mode | Binding | Scopes offered | `prepare_payment` |
|---|---|---|---|
| `mock-loopback` | loopback host AND loopback base URL (enforced at startup) | all four | registered when the token has the scope |
| `public-readonly` | https base URL | status, check, payment.read | **never registered, scope never offered** |

There is no flag that enables preparation on a public endpoint. That needs a separate remote security review and new code.
Both modes have no owner/approval/device/vault/ledger HTTP route (403).

## OAuth

Ported pattern from DIAPORIA Agent Commerce PR #9: RFC 9728 + RFC 8414 metadata, RFC 7591 dynamic registration, code +
PKCE S256 only, exact redirect match (loopback port may vary), RFC 8707 audience-bound tokens, 15-min access tokens,
rotating refresh tokens with reuse detection, RFC 7009 revocation, RFC 9207 `iss`. Consent page has a per-request CSRF
token and requires a same-origin `Origin`/`Referer`. The owner can grant fewer scopes than asked; a request without
scopes gets `status.read + payment.read`. The consent sign-in is a **development placeholder** (like PR #9's owner key):
it selects the account an AI may read for; it can never approve a payment.

## Run it

```bash
cd integrations/external-interactor
npm ci
npm run typecheck
npm test            # builds, then node --test dist/tests/**/*.spec.js
npm run demo        # full local MOCK E2E, prints every step; -- --evidence out.json to save
```

The demo starts a loopback gateway, plays an external MCP host with the official SDK client, plays the human on the
consent page, prepares a payment, approves it on a simulated enrolled device, lets the MOCK clock pass the buffer and
reads back `settledVerified: true` with the ledger receipt.

## Data disclosure to the AI host

Account reference, MOCK environment flag, freeze/lockdown booleans, count of active holds by scope kind, Rapid-Use flag,
Purpose id/version/asset/allowed recipients/limits/remaining daily limit, epoch number, buffer values, request ids and
digests, Vault payment state, ledger tx id/status. Never: credential ids, device keys, WebAuthn data, contact addresses,
guardians, journal contents, Root/Vault internals, memo of other clients.

## Limitations (not verified)

- **No real MCP host has connected** (ChatGPT, Claude, Grok): NOT VERIFIED. Only the official TypeScript SDK client over
  loopback is tested.
- The owner devices are the V5 **simulated** devices (soft WebAuthn authenticator). Nothing here verifies hardware
  authentication, biometric-only UV, OS or process isolation. UV alone does not prove a biometric.
- MOCK ledger only; no NEAR testnet/mainnet transfer, no real e-mail.
- The approval-request table lives in the adapter's own SQLite file next to the V5 databases. The durable payment
  authority (capability ids, payments, buffer, holds) stays in the Vault/Root; a production design should move the
  request record into the Root/Vault domain.
- Rate limits and pending-request caps are per process (pending: 3 per AI client, 10 per account; awaiting amounts are
  reserved against the daily limit for at most 15 min, so several clients of one account can still crowd it out until
  the owner declines). The limiter resets all keys above 10 000 keys.
- `get_payment_status` shows a client only the requests it prepared.
- The memo is reduced to printable ASCII without quotes, pipes, backslashes or backticks before it is stored or shown.
- `taskRef` binding is checked by the adapter; the Vault verifies the signature over it but does not interpret it. A
  device-signed capability is a bearer object for anyone with General-Zone access, so the GZ client must stay off the AI
  path (today only `OwnerPort.submit` calls PROPOSE).
- No process isolation in V0: the harness and `serve:mock` run gateway, adapter and simulated devices in one process;
  the separation is by object reference (frozen `AiPort`). The source scan test is a substring check, not a proof.
- `settledVerified` binds recipient, amount and paymentId of the MOCK receipt; sender and asset must be bound too before
  any real ledger.
- `public-readonly` requires an https base URL but does not terminate TLS itself (a reverse proxy is assumed).
- In V0 the OwnerPort is an in-process object used by the harness. A production device app needs an authenticated
  channel to it (device-bound session); its authority still comes only from the Vault-verified assertion.
- Fee estimate is the MOCK ledger's zero fee.
