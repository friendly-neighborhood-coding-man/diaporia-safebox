# SafeBox V4 architecture: intent-bound authorization and recovery closure

V4 is an extension of V3 (`feature/v3-purpose-recovery`, Draft PR #5, head `6d71cd0`). Every V3 component, rule and test is kept; V4 adds a protocol layer selected by `state.protocol = 'safebox.v4'` and a separate genesis extension. Nothing here is deployed. Nothing touches Mainnet, real funds or live credentials.

## What V4 changes, in one paragraph

V3 left two recovery residuals open. R-1: a stolen DAILY key plus colluding guardians, identity verifiers and notification channels could reconstitute the whole authority set after 72 hours of owner silence. R-3: a compromised or unavailable guardian / identity-verifier majority could block legitimate recovery forever, because there was no way to replace them. V4 closes R-1 by making a reconstitution require an explicit authorization from an independent Owner Recovery Credential (ORC) bound to the exact replacement set, and by terminating unapproved cases at the deadline. It closes R-3 with an emergency participant-replacement procedure (independent evidence, electorate exclusion, sealed unanimous ballots, owner quorum, 24 h delay, atomic 1:1 replacement). Across all high-risk actions it replaces "sign the action digest" with "sign a canonical AuthorizationIntent" that binds the action, the authority state, a deterministic human summary and a one-time 120 s challenge.

## Components

| Component | Code | Role | Trust |
|---|---|---|---|
| Purpose Root (V4 state machine) | `src/v4/root/chain.mjs` (handlers), `src/v3/root/service.mjs` (append-only store, `chain` parameter) | Verifies every authority transition; the only writer of authority state | Trusted; deterministic; replayable |
| Intent verifier | `src/v4/intent/intent.mjs` | Rebuilds the AuthorizationIntent from Root state + action + grant and compares canonically; verifies grant, signature, APC, screen evidence; consumes the nonce | Part of the Root |
| Summary renderer | `src/v4/intent/summary.mjs` | Deterministic structured summary, text rendering and pixel-free "screen" rendering from verified state, never from AI text | Part of the Root and of every owner device |
| Challenge service | `src/v4/intent/intent.mjs` (`ChallengeService`) | Issues signed one-time grants (256-bit nonce, 120 s, bound to account, chain, action digest, credential) | Independent party; cannot authorize anything alone |
| Recovery service V4 | `src/v4/recovery/service.mjs` | Dispatches notifications, drives deadlines (`tryComplete`, `tryExpire`, `tryGovExecute`) | Untrusted for authority: it can only submit transitions the Root checks |
| Tally service | `src/v4/ballot/ballot.mjs` (`TallyService`) | Opens sealed ballots (X25519 + HKDF-SHA-256 + AES-256-GCM) and signs the result | Trusted for dissent confidentiality only; cannot fabricate an approval |
| Adjudicators (3) | keys in `src/v4/kit.mjs` | Sign verdicts (COMPROMISED / MISCONDUCT) for an accused participant; quorum 2 | Independent parties |
| ORC (`orc-1`) | `src/v4/kit.mjs` | Offline owner recovery key with its own trusted display (SIMULATED) | Owner device; never a payment, Purpose or freeze authority |
| APC keys | `SimulatedProtectedConfirmation` in `src/v4/kit.mjs` | Protected-confirmation key next to the phone passkeys (K1, K4) (SIMULATED) | Owner device |
| Execution Vault | `src/v3/vault/vault.mjs` with `chain: V4` | Replays the V4 chain itself before executing any payment | Unchanged V2-B/V3 vault |
| Independent verifier | `src/v4/supervisor/verifier.mjs` (`verifyV4`) | Replays genesis + chain + ledger + vault evidence; counts unauthorized authority changes and transfers | Independent of the Root implementation path |
| On-chain contract | `contract-v4/src/lib.rs` | NEAR contract mirroring the V4 recovery and governance rules (local sandbox only) | Local contract verified only |
| Red-team harness | `src/v4/redteam/*`, `scripts/v4/run-redteam.mjs` | LLM attacker confined to the General Zone tool surface | Untrusted by construction |

## Authority roles

| Role | Holder (simulation) | Can pay | Governance | Recovery |
|---|---|---|---|---|
| DAILY | K1 phone passkey (+APC), K2 laptop passkey | yes, within the Purpose | co-signs | consents |
| ROOT | K3 hardware key with display | no | yes (with DAILY) | consents |
| FREEZE | K4 passkey (+APC) | no | freeze only | consents |
| RECOVERY | K5 hardware key with display | no | co-signs recovery-key rotation | consents |
| ORC | `orc-1`, offline, own display | **never** | only `ORC_REPLACE`, owner-quorum member for governance cases | authorizes / cancels a case; may attest an open |
| Guardians g1..g3, IDVs idv-1, idv-2 | independent holders | no | no | evidence only; electorate for emergency replacement |
| Adjudicators adj-1..3 | independent | no | no | verdicts only |

## Data flow of a high-risk action

1. The owner's device (not the AI) asks the challenge service for a grant for `(action digest, credential)`.
2. The device builds the AuthorizationIntent and the deterministic summary from a verified replica of the Root state.
3. The trusted path shows the summary (hardware display / protected confirmation; SIMULATED here).
4. The human decides; only then the device signs the intent digest (WebAuthn assertion with UV for passkeys, Ed25519 for hardware keys, plus an APC signature over the exact prompt text where enrolled).
5. The Root rebuilds the intent from its own state, compares it canonically, verifies the grant, the signature and the confirmation, consumes the nonce in the same transition and applies the action.

## Where the code is

```
src/v4/common/v4.mjs          domains, digests, signers
src/v4/root/chain.mjs         V4 handlers, genesis extension, approval delegate, R-1 / R-3 rules
src/v4/intent/intent.mjs      AuthorizationIntent, ChallengeService, verifyIntentApproval
src/v4/intent/summary.mjs     deterministic summaries and renderers
src/v4/ballot/ballot.mjs      sealed ballots and tally
src/v4/recovery/service.mjs   notifications and deadline driver
src/v4/recovery/sim.mjs       legitimate owner flows, governance helpers
src/v4/recovery/matrix.mjs    32-subset matrix and named scenarios
src/v4/supervisor/verifier.mjs independent V4 verifier
src/v4/redteam/*              V4 attacker tool surface, prompt, campaign driver
src/v4/kit.mjs, world.mjs     owner world and in-process wiring
contract-v4/                  NEAR contract (local)
scripts/v4/                   matrix, mutation, OS matrix, red-team runners
tests/v4/                     V4 suites
```

## Reproduce

```
npm ci
npm run v4:test                 # V4 JS suites
npm test                        # all JS suites (V1..V4)
npm run test:contract-v4        # Rust contract tests (V4)
npm run test:contract-v3        # Rust contract tests (V3, regression)
npm run v4:matrix               # docs/evidence/v4/recovery-matrix.{json,md}
npm run v4:mutations            # docs/evidence/v4/mutations.json
sudo npm run v4:os              # docs/evidence/v4/os/os-matrix.json (Linux, root)
npm run v4:redteam -- --scenario A_r1 --model claude-opus-4-8 --turns 10 --rounds 2 --budget 3 --label X
```

See `SECURITY-EVALUATION.md` for results and `RESIDUAL-RISKS.md` for what V4 does not solve.
