# SafeBox V6 security evaluation: dual biometric authorization, Gmail alerts, Emergency Freeze

Branch `claude/project-thread-xfzte9`, Draft PR #13. Never merge. The frozen PRs #9 and #10 are untouched.

Everything here runs on a MOCK ledger: no NEAR Testnet or Mainnet, and no real funds. The "real" items are listed separately in §6, each with its own evidence.

## 1. What V6 adds

| Control | Where | Enforced by |
|---|---|---|
| Per-transaction owner approval | `src/v6/vault/payment-approval.mjs` | Vault, at PROPOSE (independent verifier re-checks) |
| Fingerprint gate for fingerprint-only credentials | `src/v6/device/biometric.mjs`, `src/v6/root/chain.mjs` `checkGates` | Root (commands) and Vault (payments) |
| Durable single-use payment challenges | `src/v6/vault/vault.mjs` `v6_challenges` | Vault, survives restart |
| Emergency Freeze console | `src/v6/emergency/console.mjs`, `page.mjs` | Console checks, then Root and Vault |
| Owner device rebuilds what it signs | `src/v6/kit.mjs` `approvePrepared` | Device |
| Gmail transport (send-only) | `src/v6/notify/gmail.mjs` | Transport |
| Independent V6 verifier | `src/v6/supervisor/verifier.mjs` | Replays Root, ledger, Vault evidence and journal |
| Closeout of verifier gaps E1, E3 and Rapid-Use | `src/v5/supervisor/verifier.mjs` | V5 verifier |

**Payment binding.** Each payment approval binds:

- account, chain, credential, recipient, asset, exact amount
- Purpose id and version, Epoch, policy version
- request id and request digest, summary digest
- challenge nonce, approval expiry, required assurance

The capability `taskRef` is the hash of that binding. The Root-pinned one-time challenge binds the request digest and the credential.

## 2. Workflow A: AI-prepared payment

1. The External AI Interactor calls `prepare_payment` over MCP. The request waits as `AWAITING_OWNER_APPROVAL`.
2. The owner device shows the exact summary.
3. The owner approves:
   - a Windows Hello UV assertion over the paycap digest, and
   - for a fingerprint-only credential, a gate statement signed by the enrolled gate key over the same digest and challenge nonce.
4. The Vault verifies the binding, challenge, gate, nonce single-use and assurance level, then buffers the payment.
5. MOCK settlement happens only after the fixed 600 s buffer. The V5 Risk Engine, holds and the 26 h horizon are unchanged.
6. The independent verifier re-derives every approval from Root state at proposal time.

## 3. Workflow B: alert to Emergency Freeze

1. A burst from a stolen key makes the Risk Engine open an incident.
2. The outbox sends an alert carrying a random, expiring locator link. The link names the incident and carries no authority.
3. Opening the link (GET) changes nothing. The page is static and embeds no incident data.
4. The owner signs in: a WebAuthn assertion over a session statement bound to the console origin. That gives an HttpOnly, SameSite=Strict cookie plus a CSRF token, and every POST needs the exact Origin and JSON.
5. The console prepares the FREEZE from **trusted state only**. The incident must exist in the Vault's incident table, the reason text is fixed by the console, and the scope is GLOBAL.
6. The owner types `FREEZE EVERYTHING`. The device rebuilds the command from its own Root replica and signs it only if it matches exactly (with the fingerprint gate when required).
7. Root accepts it once (single-use proposal and challenge), and the console checks that the Vault replica shows the freeze.
8. Payments refuse with `FREEZE_ACTIVE`, buffered payments are FROZEN, and recovery goes through `HOLD_RELEASE`.

**Email limits.** An email cannot approve, release, accelerate or authorize anything (attack clip 10).

## 4. Results (cloud, deterministic)

| Suite | Result |
|---|---|
| Root regression (V1–V6) | see `docs/evidence/closeout/root-regression-v6.txt` |
| V6 suites `tests/v6` | 51/51 |
| External interactor | 40/40 |
| V6 mutation testing | 48/48 caught, including 1 higher-order (`docs/evidence/v6/mutations.json`) |
| Mock showcase | 11/11 clips (`docs/evidence/v6/showcase/2026-11-14T1011Z-mock/`) |
| Real-device runner selftest (virtual authenticator) | pass: enroll, Workflow A, freeze, Vault refusal, verifier ok, recovery |

The first mutation pass caught 31/48. The 17 survivors were closed by 8 new tests in `tests/v6/mutation-gaps.test.mjs`:

- gate-statement fields under a valid signature;
- gate-key proof of possession;
- exact loopback RP;
- taskRef binding;
- challenge-credential binding;
- console challenge exactness;
- device check of the Root-pinned grant;
- dishonest-Vault verifier cases: challenge reuse, misreported level, delegation;
- plus V5 suites for the V5-verifier mutants.

The RS256 2048-bit minimum is enforced twice (COSE parser and signature check). The higher-order mutant that removes both is caught.

## 5. Attack clips (simulated device, MOCK ledger)

| # | Attack | Outcome |
|---|---|---|
| 01 | stolen MCP token | no payment without the owner device |
| 02 | approval without fingerprint (gate skipped, PIN only, lockout) | refused |
| 03 | amount or recipient substituted after review | `V6_BINDING_MISMATCH` |
| 04 | replayed owner approval | `CHALLENGE_ALREADY_CONSUMED` |
| 05 | mail scanner or preview GETs the link | nothing changes |
| 06 | phishing look-alike origin | assertion refused (origin bound) |
| 07 | CSRF against a signed-in owner | `ORIGIN_REJECTED` / `CSRF_TOKEN_INVALID` |
| 08 | forged or wrong-incident freeze | `INCIDENT_UNKNOWN` / `USE_EMERGENCY_FREEZE_FLOW` |
| 09 | forged UNFREEZE | refused |
| 10 | compromised or forwarded email tries to approve | email carries no authority |

## 6. Real items, each stated separately

See `docs/v6/FINAL-REPORT.md` for the status of each item: real Gmail delivery, real Windows Hello, fingerprint-only, real recording, independent review.

## 7. Trust boundary and risks

1. **The fingerprint gate is local, not hardware attestation.** A gate signature proves that the helper, running as the current user on the enrolled laptop, saw a WinBio MATCH for the current Windows account and then signed. A compromised OS or a modified helper could sign without a finger. The pass label is `LOCAL_FINGERPRINT_GATE_PASSED`, never "attested". The key is TPM-backed when the Platform Crypto Provider works; otherwise it is a software key, and the enrollment record says which.
1b. **Gate freshness (real-device finding, runs 7 and 8).** Earlier gate builds produced a WinBio MATCH while the owner states he did not touch the sensor (power-button sensor on this laptop). Root cause unresolved: incidental contact or a queued sample. The final helper (cb60433) requires a mouse click on Start (keystrokes cannot arm it), a 3 s quiet window in which any sensor result is discarded, a capture of at least 700 ms, and a mouse "Yes, I touched it" after the MATCH ("No" refuses as `BIOMETRIC_TOUCH_DISOWNED`). Runs 8b and 10 (hands off) were refused; run 9 (deliberate touch + Yes) approved. Residual: a stray touch followed by a careless "Yes" approves; the disown path was not exercised on the real device; these helper changes were not independently reviewed.
2. **Windows Hello UV may be a PIN.** The WebAuthn UV flag does not say which modality was used. "Fingerprint only" therefore rests on the separate gate, never on UV.
3. **Same-user malware.** Malware running as the owner on the laptop could drive both the browser and the helper. This is the residual risk carried over from earlier reviews (SR-01 class). The gate raises the cost, because it needs a physical MATCH unless the helper is replaced, but does not remove the risk.
4. **Loopback RP (V3 change).** Genesis now accepts `rpId "localhost"` with origin `http://localhost:<port>` exactly. This exists for the owner-run local console and bridge, and is a secure context in browsers. Any other http origin is still refused (tested). A deployment should use an https RP.
5. **Freeze link reach.** The locator link works only while the console is reachable from the device that opens it. With a localhost console, that means the laptop itself.
6. **Gmail.**
   - Send-only scope; refresh token stored outside the repository.
   - API acceptance is not inbox delivery.
   - A phished owner could still be lured to a look-alike page. Login assertions are origin-bound, and the email carries no authority.
7. **Vault-supplied history.** The verifier replays the evidence the Vault keeps. A Vault that drops every trace of a payment, including ledger tx statements, is detected by the V5 ledger pass, not by the V6 pass.
8. **Windows-only test failure.** `tests/v2/drills.test.mjs` (a six-process reservation race) fails on the owner's laptop and passes on Linux. It predates V6 and is unrelated, but unexplained.
9. **No CI.** GitHub Actions has had no runner since 2026-11-03, so all results are local runs.
