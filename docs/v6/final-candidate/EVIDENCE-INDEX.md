# Evidence index: SafeBox V6 final candidate `a8ce018`

Frozen code: `a8ce01840d79166403aec159c8c05e70bd916721`. All runs were made in the cloud container (Linux, Node 22,
running as root), MOCK only, with synthetic keys. Private paths are redacted as `<repo>`, `<cloud-tmp>`, `<evidence-run>`
and `<scratch>`. Files are under `evidence/` unless stated otherwise.

## Submission-critical checks

| # | Check | Command (from repo root) | Code SHA | Result | File |
|---|---|---|---|---|---|
| 1 | Root dispatch reproduction (before) | `node docs/v6/final-candidate/evidence/root-dispatch.mjs .` (V3, V4, V5, V6; inherited and planted names) | 60cfd20 | V3/V4 commit 2 names, V5/V6 commit 8; planted function sets epoch 1 -> 99 in all four | `root-dispatch-60cfd20.json` |
| 2 | Root dispatch reproduction (after) | same | a8ce018 | 0 commits; seq, head, nonces, epoch and state hash unchanged | `root-dispatch-a8ce018.json` |
| 3 | New regressions fail on the old code | `node --test tests/v3/prototype-action.test.mjs` on 60cfd20 | 60cfd20 | 4/4 fail (as intended) | `regression-on-60cfd20.txt` |
| 4 | Baseline full suite | `npm test` | 60cfd20 | 573/573 | `baseline-60cfd20.tap` |
| 5 | Full Root + V2..V6 suite incl. V2/V3 OS-principal tests | `npm test` (from a world-readable worktree) | a8ce018 | **586/586** | `full-suite-a8ce018.tap` |
| 6 | MCP external interactor | `npm test` in `external-interactor/` | a8ce018 | 40/40 | `interactor.tap` |
| 7 | Targeted mutations (#20, Gmail, F1, termSafe, viewer) | `node scripts/v6/reconcile-mutations.mjs` | 80b3d23 | 15/16; the survivor (O_NONBLOCK removed) is detected only as a FIFO-open hang, not as `# fail` | `reconcile-mutations-80b3d23.json` |
| 8 | Full V6 mutations | `node scripts/v6/mutations.mjs` | 80b3d23 | 74/76 (the known redundant nonce pair; unchanged label) | `mutations-v6-full-80b3d23.json` |
| 9 | Full V5 mutations | `node scripts/v5/mutations.mjs` | 80b3d23 | 51/52; survivor "Verifier: flow from the vault row" also survives at 60cfd20 (pre-existing) | `mutations-v5-full-80b3d23.json`, `v5-mutant-flow-60cfd20.json` |
| 10 | CodeQL (security-extended) | GitHub Actions run 43627930882 on `security-audit/codeql-v6-final` | a8ce018 (+ audit workflow) | success, 15 warnings (16 at 60cfd20); gmail-oauth-setup race closed; none new and exploitable | `codeql-a8ce018.txt` |
| 11 | GitHub CI "SafeBox CI" | run 43627927935 on `integration/v6-final-candidate` | a8ce018 | success: node 22, node 24, Rust contract, v2-os-isolation | (GitHub run page) |
| 12 | MOCK showcase | `node scripts/v6/showcase.mjs --out <evidence-run>/showcase-mock` | a8ce018 | 11/11 clips | `showcase.log`, `showcase-mock-a8ce018/` |
| 13 | Runner selftest, recording flags | `node scripts/v6/real-device.mjs --selftest --attack-denials --demo --open-edge` | a8ce018 | 8/8 attacks refused, FREEZE_ACTIVE, settledWhileFrozen 0, verifier ok, recovery ok, bridge secret absent from logs and trace (on Linux `--open-edge` falls back to the manual step) | `selftest-demo-attacks-a8ce018.log`, `selftest-demo-attacks-a8ce018/` |
| 14 | Runner selftest, default flags | `node scripts/v6/real-device.mjs --selftest` | a8ce018 | pass, 7 bridge approvals, HOLD_RELEASE accepted | `selftest-default.log` |
| 15 | Supply chain / secret scan | `node scripts/v6/supply-chain.mjs` | a8ce018 | 0 secrets; SBOMs written | `supply-chain-a8ce018/` |
| 16 | Independent review, full diff | separate reviewer, `60cfd20..b2377da` | b2377da | PASS_WITH_ISSUES (F1 MEDIUM, F2 LOW, F5, F6, F8, F9) | `../INDEPENDENT-REVIEW-ROUND1-b2377da.md` |
| 17 | Independent review, delta | separate reviewer, `b2377da..80b3d23` (+ a8ce018 open-edge check) | 80b3d23 | PASS_WITH_ISSUES: F1 fixed, fuzz 1764 attempts 0 commits; D2..D6 LOW, fixed or labelled | `../INDEPENDENT-REVIEW-ROUND2-DELTA-80b3d23.md` |

`80b3d23` differs from `a8ce018` only in `scripts/v6/real-device.mjs`, which no mutation targets. Checks 5, 6 and 10 to 15
were run on `a8ce018` itself.

## Separate tracks (not part of the candidate)

| Track | Branch / head | Result | File |
|---|---|---|---|
| SSTP PR #27 verification | `security-research/sstp-pr27-verification` fdd302c (on d6172ec) | **PARTIAL FIX**: file swap after open refused; directory swap-and-swap-back returns SUCCESS with foreign bytes; real race won 61/10/18 of 3000 per run; unit tests catch 3/9 removed protections; no OS tests | `../SSTP-PR27-EVALUATION.md` |
| V1/V2 legacy hardening (#19, #21, #23, #24) | `security-research/v1v2-legacy-hardening` 52905fb (on 83f4a04) | 594/597 in the 0700 tmp worktree (3 OS tests fail only on path permissions), OS tests 6/6 from a readable worktree; legacy mutations 8/9 (survivor equivalent) | on that branch: `docs/evidence/legacy-hardening/` |

## NOT_RUN inventory

| Item | Status | Why / what it would take |
|---|---|---|
| Real owner take (fingerprint) on `a8ce018` | NOT_RUN | Needs Eric at the laptop. Last real-sensor run: run 12 on `1ff616b` |
| `--open-edge` on Windows | NOT_RUN | Windows-only code path; Linux selftest exercises only the fallback. Runbook gives the pause-and-open fallback |
| Windows CI | NOT_RUN | No Windows runner job exists |
| V6 OS isolation | NOT_RUN / NOT_IMPLEMENTED | V2/V3 Linux OS-principal tests ran as root in the container; that is not V6 isolation |
| Tenant isolation | NOT_RUN | not built |
| P1.5 independent risk context | NOT_RUN | not built |
| P2.10 / P2.11 / P2.12 | NOT_RUN | unchanged from the 60cfd20 freeze |
| NEAR Testnet | NOT_RUN | no funded accounts; RPC blocked from cloud; no blockchain transactions by rule |
| cargo / Rust contract locally | NOT_RUN locally | ran in GitHub CI (check 11) |
| advisory-db / `cargo audit` | NOT_RUN | no network route to the advisory DB |
| Real Gmail send on `a8ce018` | NOT_RUN | MOCK outbox only; last real sends were runs 5..10 on earlier V6 commits |
| SSTP `tests/os` | NOT_RUN / does not exist | PR #27 has no OS-level tests |
| Hardware attestation of the fingerprint | NOT_IMPLEMENTED | FINGERPRINT_ONLY_LOCALLY_VERIFIED only |

Residual-risk labels are unchanged and listed in `README.md`.
