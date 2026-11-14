# SafeBox V6 submission: evidence index

Paths are repository-relative unless marked **laptop** (kept on the owner's laptop, never uploaded unredacted).
"SIMULATED" = Chromium virtual authenticator / emulated fingerprint helper; "REAL" = owner's laptop, owner present.

## Frozen-candidate verification (`60cfd20`)

| Evidence | Path / location | Proves | Label |
|---|---|---|---|
| Root test suites | CI `SafeBox CI` run on `security-fix/v6-codeql` (Node 22/24, contract, v2-os-isolation); local 573/573 | No regression; CQ-1/CQ-2 regression tests | Linux CI + local |
| MCP interactor tests | `integrations/external-interactor` `npm test` 40/40 (local) | AI-facing interface unchanged | local |
| MOCK showcase, 11 clips | `docs/evidence/v6/showcase/2026-11-14T1649Z-mock/` (`summary.json`, traces, SHA256SUMS; `git` = 60cfd20) | Workflows A/B + 10 attack clips | MOCK, SIMULATED DEVICE |
| Runner selftest with attack denials, demo mode | `docs/evidence/v6/submission/selftest-attack-denials-60cfd20/` | Runner plumbing; 8/8 attack attempts refused; FREEZE, FREEZE_ACTIVE, verifier ok, HOLD_RELEASE; bridge secret not printed | SIMULATED (emulated helper) |
| CodeQL re-scan of the V6 patch | Actions run 43616892232 (`security-audit/codeql-v6-fix`), Security tab | Targeted V6 alerts closed; remaining alerts triaged | CI |
| CodeQL re-scan of the SSTP patch | Actions run 43616895145 (`security-audit/codeql-sstp-fix`) | `install.mjs:68` closed | CI |
| CodeQL baseline | runs 43615725041 (V6), 43615726867 (SSTP) | 16 / 17 warnings, 0 errors | CI |
| Mutation run on the patch | `docs/evidence/v6/submission/mutations-e658805.json` | 74/76, same 2 known survivors | local |
| Independent review of the patches | `CODEQL-TRIAGE.md` "Independent review" | round 1 PASS_WITH_ISSUES, round 2 PASS | review |

## Earlier V6 evidence (still valid: security-relevant code unchanged since `1ff616b`)

| Evidence | Path / location | Proves | Label |
|---|---|---|---|
| Hardening report + coverage matrix | `docs/v6/hardening/HARDENING-REPORT.md` | P0/P1 items, labels, 5 review rounds (PASS_WITH_ISSUES, no open HIGH/MEDIUM) | |
| Same-user signing analysis | `docs/v6/hardening/P0-1-SAME-USER-SIGNING.md`, `docs/evidence/v6-hardening/p0-1-*.txt` | INHERENT_RESIDUAL bound, HIGH_ASSURANCE fails closed | |
| Real-device run 12 (final gate build) | `docs/evidence/v6-hardening/p0-4-laptop-run12.md`; raw **laptop** `D:\APORIA\safebox-v6-laptop-runs\hardening-run12` | PAYMENT, FREEZE, HOLD_RELEASE with real WinBio MATCH + WINBIO_TPM gate key | REAL, FINGERPRINT_ONLY_LOCALLY_VERIFIED, MOCK ledger, MOCK email |
| Real-device run 11 | `docs/evidence/v6-hardening/p0-4-laptop-run11.md` | full command text in gate windows (owner-attested) | REAL |
| Real Gmail alert | `docs/v6/FINAL-REPORT.md` (runs 5/6) | Gmail API accepted; inbox receipt owner-attested | REAL GMAIL |
| Mutation testing | `docs/evidence/v6-hardening/mutations-full-final.json` (74/76; 2 survivors are redundant nonce checks behind a PRIMARY KEY) | Tests catch removed checks | |
| Supply chain | `docs/evidence/v6-hardening/supply-chain/` (lockfile integrity, secret scan 0, CycloneDX SBOMs) | Local supply-chain checks | local only |

## Submission recording (pending the owner)

| Evidence | Location | Status |
|---|---|---|
| Split-screen take (OBS, real Owner Console + live terminal) | **laptop** `D:\APORIA\safebox-v6-laptop-runs\submission-take-01\` (raw video, `summary.json`, `trace.jsonl`, `SHA256SUMS`, `owner-attestation.md`) | NOT_RUN: needs the owner at the laptop for the fingerprint touches |
| Edited, redacted video | to be produced from the take | NOT_RUN |

## SSTP (separate partial research)

| Evidence | Path | Label |
|---|---|---|
| SSTP docs and partial results | branch `experiment/secure-transition-v0` (`docs/secure-transition/PARTIAL-RESULTS.md`, `EVIDENCE-MATRIX.md`) | PARTIAL EVIDENCE: in-process tests only; OS isolation, containment, A/B transition, crash recovery NOT_RUN |
| verifySlot TOCTOU fix | branch `security-fix/sstp-verifyslot` `1952768`, unit 31/31 | patch only; does not change the PARTIAL label |
