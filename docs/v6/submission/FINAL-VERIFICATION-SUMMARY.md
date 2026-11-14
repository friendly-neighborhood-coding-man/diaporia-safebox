# SafeBox V6: final verification summary (submission freeze, 2026-11-14)

**Status: READY_FOR_SUBMISSION_REVIEW.** No merge, no deployment, no real money, no blockchain transaction.

## 1. Frozen candidate

- **V6 demo candidate: `60cfd20bbb54ccc774b2c108cc18e0a2c93a5563`** on `security-fix/v6-codeql` (parent chain:
  `8cd505b` PR #15 hardening, `bf7403d` PR #13 V6). Later commits on the branch are documentation and evidence only.
- SSTP patch (separate partial research): `d6172ec` on `security-fix/sstp-verifyslot` (parent `c256ffa`, PR #16).
- Frozen source branches untouched: PR #13 `bf7403d`, PR #15 `8cd505b`, PR #16 `c256ffa`.

## 2. Verification run on the frozen candidate

| Check | Where | Result |
|---|---|---|
| Root test suites (`npm test`) | cloud container, Node 22 | **573/573** (571 before + 2 new CodeQL regression tests) |
| Linux CI `SafeBox CI` (Node 22/24, Rust contract, v2-os-isolation) | GitHub Actions, push of `security-fix/v6-codeql` | **success**, run 43617744510 on `60cfd20` (SSTP patch `d6172ec`: run 43617745971 success) |
| MCP interactor (`integrations/external-interactor`) | container | **40/40** |
| MOCK showcase, 11 clips (`--no-video`) | container, `docs/evidence/v6/showcase/2026-11-14T1649Z-mock` | **11/11**, `git` = 60cfd20 |
| Real-device runner selftest, `--attack-denials --demo` | container, Chromium virtual authenticator + emulated fingerprint helper (SIMULATED) | Workflow A settled (FINGERPRINT_ONLY path), **8/8 attack attempts refused**, FREEZE via Owner Console, `FREEZE_ACTIVE`, 0 settled while frozen, verifier ok, HOLD_RELEASE accepted; bridge secret absent from the terminal; `docs/evidence/v6/submission/selftest-attack-denials-60cfd20` |
| Runner selftest, default flags | container | unchanged behaviour (no attack phase, full bridge link printed as before) |
| Mutation testing (`scripts/v6/mutations.mjs`) | container, separate worktree at `e658805` | **74/76** (same 2 known survivors), section 5 |
| CodeQL re-scan | Actions run 43617748239 (V6), 43617751244 (SSTP) | targeted findings closed; see CODEQL-TRIAGE.md |
| Independent review | 2 rounds | round 1 PASS_WITH_ISSUES (1 MEDIUM, SSTP), round 2 **PASS** |
| SSTP unit tests | container | **32/32** (30 + 2 new) |
| Real owner take (Windows Hello + real fingerprint + OBS) on `60cfd20` | owner's laptop | **NOT_RUN**: needs the owner present (VIDEO-STORYBOARD.md) |

## 3. Security findings: final state

| Severity | Item | State |
|---|---|---|
| MEDIUM | S-1 SSTP `verifySlot` lstat-then-read TOCTOU (file and directory level) | **FIXED** (`d6172ec`); residual swap-and-swap-back without `openat`, needs slot write access |
| LOW | V6-1 credentials loader race / FIFO | FIXED |
| LOW | V6-2 OAuth token file check-then-write | FIXED (exclusive create, fchmod) |
| LOW | V6-4 terminal log injection in the demo terminal | FIXED (`termSafe`) |
| LOW | Demo: bridge secret in terminal / address bar / leftover file | FIXED (`--demo`, replaceState, exclusive file deleted at exit) |
| LOW (open) | L-2/L-3 V1 key-file stat-then-read; L-7 legacy `sh -c` with install path | not patched (frozen legacy, not exploitable beyond access that already defeats the control) |
| — | L-1, L-4, L-5, L-6, L-8, L-9 legacy; test fixtures | NOT_EXPLOITABLE / TEST_ONLY |
| INHERENT_RESIDUAL | P0.1 same-user process can sign with the Windows gate key (LOCAL_GATE) | unchanged; HIGH_ASSURANCE fails closed; independent signer BLOCKED_OPERATOR_HARDWARE |
| NOT_RUN | P1.5 independent risk context, tenant isolation, OS isolation, NEAR Testnet, Windows CI, advisory-db audit | unchanged |

No HIGH or MEDIUM finding is open in the V6 candidate.

## 4. Exact verification scope

- **Interface-level only.** Attack denials show that the SafeBox interfaces (MCP gateway, device, Vault, Root, Owner
  Console, gate server) refuse the attempt. They say nothing about native code, OS or kernel compromise, launcher
  compromise or hardware attacks.
- **Attacker side simulated.** Attacks use the simulated `k1-phone` credential, a second MCP login, recorded artefacts
  and local HTTP calls. None prompts the owner.
- **Fingerprint:** "FINGERPRINT_ONLY_LOCALLY_VERIFIED" means WinBio MATCH + gate-key signature + post-MATCH Yes on the
  owner's laptop. Not hardware attestation; same-user malware can sign with the gate key (INHERENT_RESIDUAL).
  Windows Hello UV alone may be a PIN. Last real-sensor run: run 12 on `1ff616b`; Root, Vault, verifier and gate code
  are unchanged between `1ff616b` and `60cfd20`.
- **Ledger:** MOCK. "Settled" = a MOCK ledger receipt. No chain, no funds.
- **Email:** MOCK outbox in the submission take. Real Gmail was verified earlier (runs 5/6, owner-attested receipt).
- **SSTP** is a separate partial research result (in-process tests only) and not a production security guarantee.

## 5. Mutation testing

`scripts/v6/mutations.mjs` at `e658805` (first patch round), separate worktree: **74/76 caught, 0 pattern errors**
(`docs/evidence/v6/submission/mutations-e658805.json`), identical to the hardening baseline. The 2 survivors are the
known redundant ones ("V6 challenge nonce single-use removed", "P0.3: in-transaction challenge check removed"): the
nonce PRIMARY KEY still refuses the reuse. The round-2 delta (`e658805..60cfd20`) touches none of the mutated
Root/Vault/verifier/gate code (it changes the runner scripts, the Gmail loader, the terminal sanitizer and one line of
the bridge page), so the mutation run was not repeated on `60cfd20`.
