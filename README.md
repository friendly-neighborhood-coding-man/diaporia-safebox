# DIAPORIA SafeBox

**An AI agent can prepare a payment. Only the owner, on an enrolled device, can approve it.**

SafeBox is an experimental capability-security layer for AI agents that spend money. The agent works through a scoped
MCP interface that can read status and *prepare* one exact payment request. It cannot sign, approve or settle anything.
The owner approves that exact request on a separately enrolled device (passkey, plus a local fingerprint gate on Windows),
a Vault re-checks the approval against a signed Root of authority, and an independent verifier checks every effect
afterwards. If something looks wrong, the owner can trigger an Emergency Freeze that blocks new payments.

> **Read this first.** In the submitted version (V6), payments settle on a **MOCK ledger**. **No NEAR Testnet or
> Mainnet transaction has ever been sent by this project.** The NEAR-specific code (a Rust `near-sdk` contract and a
> `near-api-js` executor) is tested against the `near-sdk` unit-test VM and a simulated chain only. See
> [NEAR integration and its exact scope](#near-integration-and-its-exact-verification-scope).

| | |
|---|---|
| Submission branch | `submission/near-hackathon-2026` |
| **Frozen code commit** | **`a8ce01840d79166403aec159c8c05e70bd916721`** |
| What is after that commit on this branch | documentation and evidence only (`docs/`, `README.md`); see [Verify the freeze](#verify-the-code-freeze) |
| Status | Experimental research prototype. Not production software. Not audited. Do not use with real funds. |
| Hackathon | Built during NEAR HACKATHON 2026 (all commits are from 2026-11-12 to 2026-11-14) |
| License | MIT ([LICENSE](LICENSE)) |

---

**Security roadmap landing page:** [website source](docs/landing/index.html) · GitHub Pages publication requires enabling Pages for the `docs/` directory on this branch.

## Contents

1. [Problem](#problem)
2. [Core architecture](#core-architecture)
3. [NEAR integration and its exact verification scope](#near-integration-and-its-exact-verification-scope)
4. [Scoped MCP interface](#scoped-mcp-interface)
5. [Independent owner authorization](#independent-owner-authorization)
6. [V6 MOCK-ledger workflow and Emergency Freeze](#v6-mock-ledger-workflow-and-emergency-freeze)
7. [Videos](#videos)
8. [Evidence: verified and not verified](#evidence-verified-and-not-verified)
9. [Run X, observe Y](#run-x-observe-y)
10. [Known limitations and residual risks](#known-limitations-and-residual-risks)
11. [Test reports and security reviews](#test-reports-and-security-reviews)
12. [Repository map, history and disclosures](#repository-map-history-and-disclosures)
13. [Planned security boundary: a sealed sensitive core](#planned-security-boundary-a-sealed-sensitive-core)

---

## Problem

If an AI agent holds a wallet key, a prompt injection, a malicious tool result or a compromised MCP client can make it
pay the wrong recipient, the wrong amount, or pay twice. Asking the agent to "be careful" does not help when its
instructions are the thing under attack.

SafeBox separates the two roles:

- **The agent decides what to propose.** It can read the account's status, check a payment against policy and prepare an
  immutable approval request for one exact payment.
- **The owner decides what executes.** Execution requires a fresh owner signature over that exact request, produced on an
  enrolled device. A stolen MCP token, a stolen payment key, a changed amount or recipient, a replayed approval or an
  email link cannot substitute for it.

## Core architecture

```
 External AI (MCP client)
        |  OAuth-scoped MCP: get_safebox_status, check_payment, prepare_payment, get_payment_status
        v
 External Interactor gateway  ----- never signs, never settles ------------------------------+
        |  immutable approval REQUEST (recipient, exact yoctoNEAR amount, expiry)            |
        v                                                                                    |
 Owner device (passkey / Windows Hello WebAuthn  +  local fingerprint gate on Windows)        |
        |  owner signature over the exact command, rebuilt from the Root                    |
        v                                                                                    |
 Root of authority (signed, hash-chained journal: purposes, credentials, holds, freezes)     |
        |  replica                                                                           |
        v                                                                                    |
 Vault  -- verifies approval vs Root, applies a fixed settlement buffer, refuses when frozen  |
        |                                                                                    |
        v                                                                                    |
 Ledger adapter (V6: MOCK ledger)        Independent verifier (re-checks every effect) <-----+
        ^
 Emergency Owner Console: email alert -> link (navigation only) -> owner-signed FREEZE -> hold / recovery
```

Main code locations (all at the frozen commit):

| Component | Path |
|---|---|
| V6 world, kit and labels (MOCK ledger, simulated or real owner device) | `src/v6/world.mjs`, `src/v6/kit.mjs`, `src/v6/common/` |
| Per-payment owner approval (exact amount, recipient, expiry) | `src/v6/vault/payment-approval.mjs`, `src/v6/vault/vault.mjs` |
| Root of authority (V6 on top of the V5 Root) | `src/v6/root/chain.mjs`, `src/v5/root/` |
| Fingerprint gate, WebAuthn browser bridge, command review | `src/v6/device/`, `tools/winbio-gate/` |
| Emergency Owner Console and FREEZE | `src/v6/emergency/` |
| Alerts (MOCK outbox; optional Gmail `gmail.send` transport) | `src/v6/notify/` |
| Independent verifier | `src/v6/supervisor/verifier.mjs` |
| Scoped MCP gateway (TypeScript) | `integrations/external-interactor/` |
| NEAR contracts (Rust, `near-sdk` 5.30.1) | `contract/` (V1), `contract-v3/`, `contract-v4/` |
| NEAR executor (`near-api-js` 7.5.3) and V1 pipeline | `src/v1/` |

SafeBox was built in versions V0 to V6 inside this repository; each version is kept in its own `src/vN`, `tests/vN` and
`docs/vN` folder. V6 is the submitted version and reuses the V5 Root and Vault.

## NEAR integration and its exact verification scope

What exists in code, and how far each part was verified:

| NEAR component | What it does | How it was verified | On a real NEAR network? |
|---|---|---|---|
| `contract/` (V1, Rust, `near-sdk` 5.30.1) | `execute_payment(intent, authorization, signature)`: checks an Ed25519 owner authorization over a canonical sealed intent, a per-payment cap, single-use nonces and revocation, then transfers. Designed to be called through a **FunctionCall access key limited to `execute_payment`** | `cargo test` in the `near-sdk` unit-test VM (5 tests, 15 shared test vectors with the JS side); wasm builds in CI | **No.** Built, never deployed |
| `src/v1/` executor (`near-api-js` 7.5.3) | Signs and sends the transaction with the limited key, durable SQLite CAS broker (one reservation, one signature, one effect), crash and RPC-timeout recovery, final-state verifier | `npm test` against a **simulated chain** (`npm run demo:v1`) | **No.** `npm run demo:testnet` refuses to run without operator-provided accounts and keys and exits with code 2; it was never run against Testnet |
| `contract-v3/`, `contract-v4/` (Rust) | On-chain vault variants: payment proposals and release, hard-coded governance matrix, recovery cases with owner recovery credential, no admin / upgrade / withdraw-all method | `cargo test` in the `near-sdk` unit-test VM | **No.** Never deployed |
| V5 / V6 Vault | Amounts are integer **yoctoNEAR**, asset `NEAR`, recipients are NEAR-style account ids (`vault-alice.mock`) | `npm test`, showcase, real-device runs | **No.** The V6 ledger adapter is a **MOCK ledger**; "SETTLED" means settled on that mock |

Why there is no live transaction: the build environment's network policy blocked NEAR RPC endpoints (HTTP 403 from the
egress proxy for `rpc.testnet.near.org` and `test.rpc.fastnear.com`), no funded Testnet accounts or independently held
owner keys were provisioned, and the project rules forbade creating accounts or presenting simulated hashes as chain
evidence. See [`docs/near-v1-test-report.md`](docs/near-v1-test-report.md). The operator steps for a real Testnet run are
in [`docs/near-v1-operator-guide.md`](docs/near-v1-operator-guide.md); they have not been executed.

NEAR features this design targets (hackathon "AI Security & Defense" hints): spending limits and a policy engine,
a sandboxed wallet whose execution key is a **FunctionCall access key** scoped to one method, and owner authorization
that cannot be produced by the agent.

## Scoped MCP interface

`integrations/external-interactor/` is an OAuth 2.1-scoped MCP gateway (`@modelcontextprotocol/sdk` 1.32.2). One MCP
server is created per HTTP request and bound to one verified principal; the account comes from the token, never from
tool arguments. A tool is registered only when the token carries its scope and the deployment mode offers it. There is no
generic dispatcher. The implementation is in `src/mcp/server.ts` and `src/auth/scopes.ts`.

| Tool | Scope | Effect |
|---|---|---|
| `get_safebox_status` | `safebox.status.read` | Read-only: freeze state, holds, Purpose limits, settlement buffer (redacted: no credential ids, keys or contacts) |
| `check_payment` | `safebox.payment.check` | Read-only estimate against Purpose, limits and holds. **Not an authorization** |
| `prepare_payment` | `safebox.payment.prepare` | Creates an immutable, expiring approval **request** for one exact payment. Never signs, settles or executes. Rate-limited, idempotent |
| `get_payment_status` | `safebox.payment.read` | Read-only: request state, Vault state and MOCK ledger receipt; `settledVerified=true` only when they agree |

Design and threat model: [`docs/integrations/EXTERNAL_INTERACTOR.md`](docs/integrations/EXTERNAL_INTERACTOR.md).
Verified with an in-process test MCP host (40/40 tests). Not verified with real MCP hosts (Claude, ChatGPT, Grok).

## Independent owner authorization

- **Exact binding.** The owner signs a command that the device rebuilds from the Root state: account, exact yoctoNEAR
  amount, recipient, request id and expiry. Changing the amount or recipient after the owner saw the summary gives
  `CAPABILITY_MISMATCH`.
- **One approval, one payment.** WebAuthn sign counter and durable nonces: a replayed approval gives
  `WEBAUTHN_SIGNCOUNT_NOT_INCREASING`.
- **Keys alone are not enough.** A stolen payment key without a V6 owner approval gives `V6_PAYMENT_APPROVAL_REQUIRED`.
  A stolen MCP token can only prepare a request, which waits as `AWAITING_OWNER_APPROVAL`.
- **Origin-bound.** WebAuthn origin binding; the local fingerprint gate answers HTTP 403 to requests with no or a foreign
  `Origin`.
- **Syncable passkeys refused at enrollment** (`ENROLLMENT_SYNCABLE_PASSKEY_UNDECLARED`), so the owner credential is not
  silently copied to a cloud password manager.
- **Fingerprint gate (Windows, `tools/winbio-gate/`).** Before the Windows Hello prompt, a helper asks for a fresh WinBio
  fingerprint MATCH (click-to-start, quiet phase, post-match "Yes, that was me") and signs with a per-user TPM-backed CNG
  key. This is **local verification, not hardware attestation**; see the limitations below.

## V6 MOCK-ledger workflow and Emergency Freeze

**Workflow A, a normal payment.** The AI calls `prepare_payment` (0.03 NEAR to an allowed recipient) and gets
`AWAITING_OWNER_APPROVAL`. The owner reviews the exact payment on the device and approves. The Vault verifies the approval
against its Root replica, holds it for a fixed settlement buffer (600 s, `FIXED_600`), then settles on the **MOCK ledger**.
`get_payment_status` reports `settledVerified=true` only when the Vault state and the MOCK ledger receipt match the request.

**Workflow B, Emergency Freeze.** A risk rule delays unusual spending and opens an incident. The owner gets an alert
(MOCK outbox by default) containing a link that is **navigation only**: opening it, even six times by a link scanner,
changes nothing. In the Emergency Owner Console the owner signs a FREEZE. The Root records a hold, the Vault refuses new
payments with `FREEZE_ACTIVE`, and the verifier confirms `settledWhileFrozen = 0`. FREEZE does not reverse a payment that
already settled. Recovery releases the hold only through the hold's own valid parties.

## Videos

| Video | What it shows | Length |
|---|---|---|
| **Video A: architecture overview** | Problem, trust boundaries, Workflow A and Workflow B, labelled SIMULATED CLOCK / MOCK ALERT where applicable | 102 s |
| **Video B: real-device demonstration** | One real run of the frozen commit `a8ce018` on the owner's Windows laptop: passkey enrollment, fingerprint-gated payment approval (MOCK ledger), 8 attack denials, Emergency Freeze, payment refused while frozen, recovery | 183 s |

Files (in this branch):
[Video A MP4](docs/submission/media/SafeBox-VideoA-architecture.mp4) ([captions](docs/submission/media/SafeBox-VideoA-architecture.en.srt)),
[Video B MP4](docs/submission/media/SafeBox-VideoB-real-device.mp4) ([captions](docs/submission/media/SafeBox-VideoB-real-device.en.srt)).

Video integrity (verify with `ffmpeg -v error -i <file> -map 0 -c copy -f streamhash -hash sha256 -`):

| Video | Video stream SHA-256 | Audio stream SHA-256 |
|---|---|---|
| A | `084aadc5de862d9bcc00fc4f57c477b6cdd3fe36246856c9083092a3c539eedd` | `e41f8c3e3af36c75bfe60530e104e04a82ebfb743c17314ac31ea76e4d0e4e60` |
| B | `8dce5572a72e60b2ae916ccd3663c6d9f5f377ea1616648c198ae9bca605c102` | `287d12bb0510bc4c2b9e73bb85fd08cf1f1d6100aaf07ada7a54c0c6005f0043` |

Video B is an edited cut of one screen recording. Private details (window titles holding the per-run bridge secret, the
owner's name and avatar, institution logos) were cut or boxed; the raw recording is not published. In the Video B run
the attacker side was **simulated** by the runner, the alert went to the **MOCK** outbox (no real email), and Windows Hello
UV cannot prove which modality (fingerprint or PIN) was used; the separate WinBio gate logged a fingerprint MATCH for the
3 gated approvals.

## Evidence: verified and not verified

### Verified

| Claim | Evidence | Where it ran |
|---|---|---|
| Root + V0..V6 regression suite passes on the frozen commit: **586/586** | `npm test`; [`full-suite-a8ce018.tap`](docs/v6/final-candidate/evidence/full-suite-a8ce018.tap); re-run for this submission, see [reproduction report](docs/submission/REPRODUCTION-REPORT.md) | Linux cloud container, Node 22.23.4, as root |
| Scoped MCP gateway: **40/40** tests (build, OAuth, E2E, security negatives) | [`interactor.tap`](docs/v6/final-candidate/evidence/interactor.tap); re-run | same |
| MOCK showcase: **11/11** clips pass (main demo + 10 attacks) | [`showcase-mock-a8ce018/`](docs/v6/final-candidate/evidence/showcase-mock-a8ce018/); re-run | same, Chromium virtual authenticator (SIMULATED DEVICE) |
| Real-device runner selftest: 8/8 attacks refused, FREEZE_ACTIVE, 0 settled while frozen, verifier ok | [`selftest-demo-attacks-a8ce018/`](docs/v6/final-candidate/evidence/selftest-demo-attacks-a8ce018/); re-run | same, SIMULATED DEVICE |
| NEAR contract logic: V1 5/5, V3 24/24, V4 34/34 Rust tests | `cargo test --manifest-path contract*/Cargo.toml`; V1 also in GitHub CI | `near-sdk` unit-test VM |
| GitHub CI "SafeBox CI" green on `a8ce018` (Node 22, Node 24, Rust contract + wasm build, V2 OS isolation job) | [Actions run 43627927935](https://github.com/friendly-neighborhood-coding-man/diaporia-safebox/actions/runs/43627927935) | GitHub-hosted Ubuntu |
| CodeQL security-extended on `a8ce018`: success, 15 warnings, none triaged as new and exploitable | [`codeql-a8ce018.txt`](docs/v6/final-candidate/evidence/codeql-a8ce018.txt) | GitHub Actions |
| Mutation testing: V6 74/76 killed, V5 51/52 | [`mutations-v6-full-80b3d23.json`](docs/v6/final-candidate/evidence/mutations-v6-full-80b3d23.json), [`mutations-v5-full-80b3d23.json`](docs/v6/final-candidate/evidence/mutations-v5-full-80b3d23.json) | cloud container |
| Real Windows laptop run of `a8ce018` (Video B): enrollment, fingerprint-gated approval settled on the MOCK ledger, 8/8 attack denials, FREEZE, `FREEZE_ACTIVE`, 0 settled while frozen, verifier ok, recovery ok | Video B; run summary and trace kept privately by the operator (SHA-256 `2df030c9…`, `4a6eca5c…`) | Owner's laptop, real Windows Hello + WinBio sensor |
| Two independent security review rounds of the final candidate: PASS_WITH_ISSUES, all items fixed or labelled | [round 1](docs/v6/final-candidate/INDEPENDENT-REVIEW-ROUND1-b2377da.md), [round 2](docs/v6/final-candidate/INDEPENDENT-REVIEW-ROUND2-DELTA-80b3d23.md) | separate reviewer agents |

### Not verified (NOT_RUN or NOT_IMPLEMENTED)

| Item | Status |
|---|---|
| **Any NEAR Testnet or Mainnet transaction** | **NOT_RUN.** No transaction hash exists. Contracts never deployed |
| On-chain settlement in V6 | **NOT_IMPLEMENTED.** V6 settles on a MOCK ledger only |
| Hardware attestation of the fingerprint | **NOT_IMPLEMENTED.** `FINGERPRINT_ONLY_LOCALLY_VERIFIED` only |
| Independent signer outside the owner's OS account | **NOT_IMPLEMENTED** (needs separate hardware); see LOCAL_GATE below |
| V6 OS isolation, tenant isolation | **NOT_IMPLEMENTED / NOT_RUN.** The V2/V3 Linux OS-principal tests are not V6 isolation |
| Windows CI | **NOT_RUN.** No Windows runner job exists; Windows code paths ran only on the owner's laptop |
| Real MCP hosts (Claude, ChatGPT, Grok) | **NOT_RUN** |
| Real Gmail alert on `a8ce018` | **NOT_RUN** (MOCK outbox). Real `gmail.send` alerts were sent on earlier V6 commits only |
| `cargo audit` / advisory database | **NOT_RUN** (no network route) |
| SSTP secure-update research | **PARTIAL**, kept on separate branches, not part of this submission |

Full inventory: [`docs/v6/final-candidate/EVIDENCE-INDEX.md`](docs/v6/final-candidate/EVIDENCE-INDEX.md).

## Run X, observe Y

Everything below is local and MOCK only. Nothing needs an account, key, network service or wallet. Tested on Linux with
Node.js 22.23.4 and npm 10.9.9; results of the run made for this submission are in
[`docs/submission/REPRODUCTION-REPORT.md`](docs/submission/REPRODUCTION-REPORT.md).

**Prerequisites:** Node.js **>= 22.13** (uses `node:sqlite`), npm, git. Optional: Rust with the `wasm32-unknown-unknown`
target for the contract tests. Playwright is **not** a dependency in `package.json`: the runner selftest (row 8) and
the video mode of the showcase need it installed separately (`npm install --no-save playwright && npx playwright install
chromium`); the showcase with `--no-video` (row 7) does not. ffmpeg is used only to convert showcase videos to MP4.

```bash
git clone https://github.com/friendly-neighborhood-coding-man/diaporia-safebox
cd diaporia-safebox
git checkout submission/near-hackathon-2026
npm ci
```

| # | Run | Observe |
|---|---|---|
| 1 | `npm test` | `# tests 586`, `# pass 586`, `# fail 0` (about 40 s). Run it from a directory other users can read: three OS-principal tests (V2/V3) switch to unprivileged users and need root; without root or from a private (0700) directory those three fail with `ENOENT .../run.json` or `Cannot find module` |
| 2 | `npm run demo` | V0 mock flow ends with `EXECUTED MOCK_EXECUTED`, `REPLAY_BLOCKED`, `MOCK_EFFECTS 1` |
| 3 | `npm run demo:v1` | V1 pipeline on a **simulated** NEAR chain: `send_tx timed out -> reconciled to CONFIRMED via tx status`, attacker balance `"0"`, journal `ok:true`, and the line `NOTE: SIMULATED chain. No NEAR testnet transaction was sent.` |
| 4 | `node demo/testnet-v1.mjs; echo $?` | Prints `UNVERIFIED: NEAR testnet demo not run. Missing prerequisites: ...`, `No transaction was signed or sent.`, exit code `2` |
| 5 | `cd integrations/external-interactor && npm ci && npm run typecheck && npm test` | `# tests 40`, `# pass 40` |
| 6 | `npm run demo` (in `integrations/external-interactor`) | MCP E2E JSON with `"ledgerStatus": "SETTLED"`, `"merchantCredited": "30000000000000000000000"` (0.03 NEAR, MOCK) and a `notVerified` list naming real MCP hosts, WebAuthn hardware and NEAR networks |
| 7 | `node scripts/v6/showcase.mjs --no-video --out /tmp/sbx-showcase` (repo root) | V6 MOCK workflow: `CHECK PASS` lines for Workflow A (prepare, owner approval, buffer, MOCK settlement) and Workflow B (GLOBAL hold, Vault refuses while frozen, recovery, independent verifier), then each of the 10 attack clips, ending `11/11 clips passed`. Without `--no-video` it also records MP4 clips (Playwright + ffmpeg) |
| 8 | `node scripts/v6/real-device-selftest.mjs 47790 /tmp/sbx-st --attack-denials --demo` (needs Playwright) | The Windows real-device runner (`scripts/v6/real-device.mjs`) driven by Chromium's **virtual** authenticator: `HOLD_RELEASE: accepted`, `bridge approvals clicked: 7`, and in `/tmp/sbx-st/summary.json` 8/8 attacks `refused: true`, `paymentWhileFrozen: FREEZE_ACTIVE`, `settledWhileFrozen: 0`, `verifierOk: true`, recovery `ok: true`. The summary label still reads `REAL DEVICE AUTH` because the runner cannot tell a virtual authenticator from a real one; this output is SIMULATED DEVICE evidence |
| 9 | `cargo test --manifest-path contract/Cargo.toml`, then `contract-v3`, `contract-v4` | `test result: ok. 5 passed` (V1), `24 passed` (V3), `34 passed` (V4), all in the `near-sdk` unit-test VM. First run downloads crates (about 1 minute each) |

The real-device run (Video B) needs a Windows laptop with a fingerprint sensor and the owner present:
[`docs/v6/final-candidate/RECORDING-RUNBOOK.md`](docs/v6/final-candidate/RECORDING-RUNBOOK.md) and
[`docs/v6/OPERATOR-GUIDE.md`](docs/v6/OPERATOR-GUIDE.md).

### Verify the code freeze

```bash
git diff --stat a8ce01840d79166403aec159c8c05e70bd916721 submission/near-hackathon-2026 -- . ':(exclude)docs' ':(exclude)README.md'
# prints nothing: only docs/ and README.md differ from the frozen code commit
```

## Known limitations and residual risks

- **LOCAL_GATE (inherent residual).** The fingerprint gate key is a per-user Windows CNG key. Malware running as the same
  Windows user can ask it to sign without a finger. `HIGH_ASSURANCE` mode therefore fails closed (no isolated gate kind is
  configured). A truly independent signer needs separate hardware and is not built.
- **No hardware attestation.** The gate proves a local WinBio MATCH plus a gate-key signature plus the owner's "Yes". It
  accepts any finger enrolled in that Windows account. Windows Hello UV on its own may be a PIN or a face.
- **No V6 OS isolation.** V6 components share one OS account and process boundary on the owner's machine. The protections
  shown are interface-level: they say nothing about native code, OS or kernel compromise, or hardware attacks.
- **MOCK ledger, simulated attacker.** No NEAR network was used. Attack denials were driven by test code.
- **SSTP (secure transition / update) research is incomplete.** Its latest fix leaves a directory swap-and-swap-back race
  open (PARTIAL FIX); it lives on separate research branches and is not part of this submission.
- **Gate freshness.** Earlier gate builds reported a MATCH without a deliberate touch (root cause unresolved). The current
  gate adds a quiet phase and a post-match confirmation, but a stray touch followed by a careless "Yes" would still approve.
- Other open LOW items and the full list: [`docs/v6/final-candidate/README.md`](docs/v6/final-candidate/README.md),
  [`docs/v6/SECURITY-EVALUATION.md`](docs/v6/SECURITY-EVALUATION.md),
  [`docs/v6/hardening/P0-1-SAME-USER-SIGNING.md`](docs/v6/hardening/P0-1-SAME-USER-SIGNING.md).

## Test reports and security reviews

| Report | Link |
|---|---|
| Final candidate overview, fixes since the previous freeze, residual risks | [`docs/v6/final-candidate/README.md`](docs/v6/final-candidate/README.md) |
| Evidence index and NOT_RUN inventory | [`docs/v6/final-candidate/EVIDENCE-INDEX.md`](docs/v6/final-candidate/EVIDENCE-INDEX.md) |
| Independent review, round 1 (full diff) | [`INDEPENDENT-REVIEW-ROUND1-b2377da.md`](docs/v6/final-candidate/INDEPENDENT-REVIEW-ROUND1-b2377da.md) |
| Independent review, round 2 (delta) | [`INDEPENDENT-REVIEW-ROUND2-DELTA-80b3d23.md`](docs/v6/final-candidate/INDEPENDENT-REVIEW-ROUND2-DELTA-80b3d23.md) |
| Reconciliation ledger (patch decisions) | [`RECONCILIATION-LEDGER.md`](docs/v6/final-candidate/RECONCILIATION-LEDGER.md) |
| V6 final report and security evaluation | [`docs/v6/FINAL-REPORT.md`](docs/v6/FINAL-REPORT.md), [`docs/v6/SECURITY-EVALUATION.md`](docs/v6/SECURITY-EVALUATION.md) |
| V6 hardening report | [`docs/v6/hardening/HARDENING-REPORT.md`](docs/v6/hardening/HARDENING-REPORT.md) |
| SSTP evaluation (partial, separate track) | [`SSTP-PR27-EVALUATION.md`](docs/v6/final-candidate/SSTP-PR27-EVALUATION.md) |
| NEAR V1 test report (no live transaction) | [`docs/near-v1-test-report.md`](docs/near-v1-test-report.md) |
| Submission reproduction report | [`docs/submission/REPRODUCTION-REPORT.md`](docs/submission/REPRODUCTION-REPORT.md) |
| Submission secret and privacy scan | [`docs/submission/SECURITY-SCAN.md`](docs/submission/SECURITY-SCAN.md) |

## Repository map, history and disclosures

- `src/mock` (V0), `src/v1`..`src/v6`, `tests/`, `docs/vN/`: one folder per version; V6 is the submission.
- Repository created 2026-11-12; all commits are inside the hackathon window. Earlier work by the same author that
  SafeBox builds on conceptually (purchase authorization in
  [DIAPORIA Buy / Agent Commerce](https://github.com/friendly-neighborhood-coding-man/diaporia-agent-commerce)) is a
  separate repository; no code from it is required to run SafeBox.
- Dependencies: `near-api-js` 7.5.3, `near-sdk` 5.30.1, `@modelcontextprotocol/sdk` 1.32.2, `zod`, TypeScript, Playwright
  (showcase only), Node.js built-in `node:sqlite`. SBOMs:
  [`docs/v6/final-candidate/evidence/supply-chain-a8ce018/`](docs/v6/final-candidate/evidence/supply-chain-a8ce018/).
- AI assistance: most code and documentation was written by AI coding agents (Claude Code, Cursor) under the author's
  direction; commits show the agent as author or co-author.
- Development history of V6 is on Draft pull requests (#13, #15, #29 and others); none are merged. The submission
  branch is the frozen candidate of Draft PR #29 plus this documentation.

## Planned security boundary: a sealed sensitive core

> **DESIGN COMMITMENT — NOT IMPLEMENTED IN V6.** SafeBox aims to limit the damage caused by a compromised application or software distribution pipeline. Its future sensitive core will favor a small trusted computing base, strict default-deny interfaces, independently authorized updates, and verifiable execution over convenient hot-patching. This is a roadmap, **not a currently proven isolation guarantee**.

### Why assume the software itself could be hostile?

An attacker does not need to persuade an agent if they can compromise the software the agent trusts. A developer's GitHub account, CI/CD workflow, build environment, signing authority, or update distribution path could be compromised. A correctly signed application update can still be malicious if an attacker controls the authorized signing or release process. Nor does an honest developer guarantee that every dependency and update source remains honest.

The November 2026 *GODDESS OF VICTORY: NIKKE* PC-launcher compromise is a **real-world motivation**, not an exploit reproduced against SafeBox. The publisher reported tampered launcher scripts and distribution of malicious software; [the official NIKKE notice](https://nikke-en.com/) and [Bitdefender's launcher analysis](https://www.bitdefender.com/en-gb/blog/labs/nikke-game-launcher-malware) document the incident. The incident is not evidence that the NIKKE developer intentionally attacked users. SafeBox's research question is what damage an untrusted or compromised application could cause **even when the sensitive authority is supposed to remain separate**.

### Release objective: deliberately inconvenient to modify

Until a future deployment candidate is independently validated, the intended rule is **closed by default, including for the developer**. Convenience is not a sufficient reason to grant ordinary app or CI/CD code write access to the sensitive core.

The proposed architecture will be evaluated against these conditions:

1. **Minimal interfaces.** The agent and application may submit narrowly typed requests and read explicitly approved status. They must not receive arbitrary file, shell, signing, policy-edit, or core-update capabilities.
2. **OS-enforced separation.** The sensitive service, signing material, protected state, update controller, and independently reachable owner freeze/recovery path should not share the compromised application's effective write authority. A separate process alone does not count as isolation.
3. **Immutable code epoch.** A deployed core should execute from a verified, protected snapshot. No general in-place hot-patching; installing a candidate and activating a new epoch must be separate operations. Executed bytes must be the bytes that were verified.
4. **Independently authorized changes.** A change to executable code, authority roots, permissions, spending ceilings, or recovery rules should require an external owner-controlled approval path that ordinary app deployments cannot impersonate. Replacing an ordinary GitHub release must not replace this approval.
5. **Protected, monotonic state.** Spent budgets, used nonces, freeze state, epochs, and anti-rollback records still **must change** during normal operation. The goal is to make these changes policy-governed, auditable, and resistant to rollback—not to freeze the database forever.
6. **Fail closed and limit blast radius.** Missing or unverifiable authority, ambiguous update provenance, stale state, unexpected file changes, or unavailable verification should deny sensitive effects. Independent ceilings, expiry, buffering, and freeze are intended to bound exposure when prevention fails.
7. **Break-glass recovery is not an app API.** A wipeout or reset must not silently erase spending history, revive old credentials, lift a freeze, or re-enable a compromised epoch. Recovery must use independent owner authority and have a tested, explicit state-transfer and revocation procedure.

**Randomness is not the root of trust.** Cryptographic nonces, fresh challenges, and unpredictable audit schedules may help, but authorization rules should remain deterministic and independently verifiable. If the attacker can patch the random rule generator, randomness does not protect the core.

### Current implementation versus target

| Property | Frozen V6 submission | Future sealed-core objective |
|---|---|---|
| Agent authority | Scoped MCP tools prepare requests; no MCP signing or settlement | Preserve a request-only, minimal interface |
| Owner approvals | Exact request binding, WebAuthn UV, local Windows fingerprint-gate experiment | Independently held approval and update authority; separately trusted transaction display |
| Execution and spending | Root/Vault policy checks, fixed 600-second buffer, holds, emergency freeze; **MOCK ledger** | OS-isolated production-grade sensitive execution; independently enforced, bounded real effects |
| OS isolation for sensitive V6 components | **NOT IMPLEMENTED / NOT RUN** | Separate principals, protected update controller, explicit capability and file-descriptor boundaries |
| Code/update immutability | **NOT IMPLEMENTED** | Verified bytes, protected execution snapshots, independently approved epoch transition and rollback refusal |
| Hardware-backed independent signer | **NOT IMPLEMENTED**; local gate key is usable by same-user code | Owner-controlled independent key/approval path, with measured security properties |
| Real-chain settlement | **NOT RUN**; no Testnet/Mainnet transaction | Requires separate deployment and verification before any real-funds claim |

### Research evidence and honest limitations

- **Frozen V6 (`a8ce018`) remains unchanged.** Submission evidence includes **586/586** regression tests, **40/40** MCP interactor tests, an **11/11** MOCK showcase and a real Windows sensor demonstration against a **MOCK** ledger. These results support specific interface-level claims, **not** resistance to same-user malware or a malicious signed update. See [the V6 evidence index](docs/v6/final-candidate/EVIDENCE-INDEX.md).
- **SSTP is separate partial research.** [PR #34](https://github.com/friendly-neighborhood-coding-man/diaporia-safebox/pull/34) improves specific deterministic file-swap schedules but does **not** establish tamper-proof execution; retained writable mappings, coarse timestamp/inode reuse, and verify-then-use remain relevant. [PR #32](https://github.com/friendly-neighborhood-coding-man/diaporia-safebox/pull/32) has a failed F9 owner-log binding claim under inode reuse. [PR #33](https://github.com/friendly-neighborhood-coding-man/diaporia-safebox/pull/33) documents isolation requirements; it does not implement containment.
- **Signed-launcher scenario (Track D): `BLOCKED_BY_SAFETY_GATE / NOT_RUN`.** This experiment produced **no security validation result** and must not be described as a successful attack defense or as an observed exploit in SafeBox.
- **Threat-model limits.** The intended design does not promise to prevent every compromise, protect a fully compromised OS/kernel or boot trust root, guarantee a trustworthy app UI, reverse completed payments, prevent all service denial, or cap losses through unrelated credentials and channels. Any actual damage bound must be measured within a stated threat model and specific spending path.

### Parallel falsification sprint — research only (2026-11-15)

**Status: `READY_FOR_OPERATOR_PARALLEL_VALIDATION_REVIEW`. Nothing from this sprint was merged into V6 or deployed.** Independent integration review corrected several prototype claims:

- **Verified bytes, not verified paths.** R1 mmap, V-1 retained cross-uid writable mappings and R3 post-return rewrites defeated verify-then-open. A bounded read into a **memfd sealed first and then re-hashed**, followed by a consumer that verifies seals/digests and starts through a trusted absolute path, is the recommended **unimplemented** integration. The initial Worker A implementation was **PARTIAL**: a same-user pre-seal write delivered foreign bytes after SUCCESS. The reviewer's seal-first/re-hash correction refused that attack.
- **Owner-log integrity requires independent authority.** Inode binding was falsified by inode reuse; held descriptors, prefix hashes and unsigned chains were insufficient. Owner-signed chained entries + a signed head + an **out-of-band anchor** rejected unauthorized POLICY across scoped T1/T2 tests. However, the current `sup/` placement exposes the anchor/owner keys to a directory writer; real deployment is **NOT_RUN**.
- **Race/resource controls are helpful but not immutable execution.** Held FDs blocked N1 inode reuse, bounded reads addressed N3 growth, and returned bytes were genuine in **1,886/1,886 accepted schedules**. The path verifier remains vulnerable to writes after the final check, coarse timestamp dependence, deep-tree FD exhaustion and unnormalized `EMFILE`.
- **Signed malicious update containment is not demonstrated.** Track D was **`BLOCKED_BY_SAFETY_GATE / NOT_RUN`**; B1–B6 OS isolation and an app-independent FREEZE path remain unimplemented. No properly signed hostile package has been shown contained.

Full scoped summary: [Parallel falsification review](docs/security-research/PARALLEL-VALIDATION-2026-11-15.md). Prototype branches/evidence bundles remain with the operator, not in the submission.

**Design principle:** *Flexible intelligence. Inflexible authority.* A compromised developer account should not automatically confer control over a user's sensitive authority. Whether a deployed SafeBox can enforce that distinction remains an open engineering and verification question.

---

*Let AI explore freely. Let only authorized actions execute.*
