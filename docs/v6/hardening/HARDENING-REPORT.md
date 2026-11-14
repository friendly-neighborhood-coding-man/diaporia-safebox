# SafeBox V6 security hardening (issue #14): final report

Status: **READY_FOR_OPERATOR_REVIEW**. Nothing merged, nothing deployed, no real money, no Mainnet or Testnet transactions.

- Branch `claude/v6-security-hardening`, report commit = PR head. Frozen reference: Draft PR #13 at `bf7403d`, which is untouched.
- Code under review ends at `f80e6ac`. Later commits add documentation and evidence only.
- Labels follow issue #14: `FIXED_AND_REVIEWED`, `MITIGATED`, `FAILED`, `NOT_RUN`, `INHERENT_RESIDUAL`, `BLOCKED_OPERATOR_HARDWARE`.

## 1. Coverage matrix

| # | Item | Label | Pre-fix reproducer | Post-fix | Mutation / fault injection | Independent review |
|---|---|---|---|---|---|---|
| P0.1a | Same-user process signs with the Windows fingerprint-gate key | **INHERENT_RESIDUAL** (LOCAL_GATE), bounded | Real laptop probe: TPM key, UI policy None, signed with no fingerprint, not elevated (`p0-1-laptop-probe.txt`) | Bound tests pass (`hardening-p0-gatekey`) | P0.1 mutants 8/8, review 3/3 | CONFIRMED, round 1 |
| P0.1b | HIGH_ASSURANCE mode that refuses a same-user gate key | **FIXED_AND_REVIEWED** (fails closed everywhere) | `p0-1-prefix.txt` (4 failing) | `p0-1-postfix.txt` | included above | CONFIRMED |
| P0.1c | A fingerprint-only credential paying through LEGACY_V5 without its V6 approval (found in review) | **FIXED_AND_REVIEWED** | `p0-1-review-legacy-prefix.txt` (2 failing) | pass | HO mutant (pre-check AND transaction) caught; each half tested alone | FIXED, round 2 |
| P0.1d | Independent signer (separate OS user, service or hardware) | **BLOCKED_OPERATOR_HARDWARE** | n/a | n/a | n/a | n/a |
| P0.1e | Runs 7/8 freshness defect (stale touch) | **MITIGATED** | Real sensor R1 to R4 (`p0-1-sensor-checks.jsonl`) | Yes/No touch confirmation, 3 s quiet window, 500 ms click guard. The "No" path was verified on hardware (R3 `BIOMETRIC_TOUCH_DISOWNED`) | winbio-gate tests | Root cause: H2 not reproduced; H1 likely but unproven |
| P0.2 | Compromised console shows one command and gets another signed | **FIXED_AND_REVIEWED** for fingerprint-gate credentials | `p0-2-prefix.txt` (4 failing), `p0-2-summary-prefix.txt` (5 failing) | `p0-2-postfix.txt` | P0.2 mutants, plus 2 device mutants re-anchored to `command-review.mjs` (both caught) | CONFIRMED_WITH_ISSUES, then FIXED |
| P0.2r | Free text forging lines (including the bold amount) in the gate window (found in review) | **FIXED_AND_REVIEWED** | `p0-review3-display-prefix.txt` | pass | Review3 mutants 3/3 | FIXED, round 4 |
| P0.2u | UV-only (non-gate) credential on the console route | **INHERENT_RESIDUAL** | n/a | n/a | n/a | agreed |
| P0.2a | Windows Secure Desktop / APC-style trusted display | **BLOCKED_OPERATOR_HARDWARE** | n/a | n/a | n/a | n/a |
| P0.3 | Nonce consumption, payment commit atomicity, crash, race, idempotency | **FIXED_AND_REVIEWED** | `p0-3-prefix.txt` (crash, race, faults: 3 failing) | `p0-3-postfix.txt` | HO mutant caught; 2 single mutants survive by design (see §4) | CONFIRMED, round 1 |
| P0.3s | Settlement crash and concurrent release | **FIXED_AND_REVIEWED** (no defect; regression test added, 7734439) | test passed before the change | pass | n/a | CONFIRMED |
| P0.3v | Verifier missing a dishonest LEGACY_V5 vault (found in review) | **FIXED_AND_REVIEWED** | `p0-review3-verifier-prefix.txt` (2 failing) | pass | Review3 mutants | FIXED, round 4 |
| P0.4 | Re-test PAYMENT, FREEZE, HOLD_RELEASE on the final gate build | **FINGERPRINT_ONLY_LOCALLY_VERIFIED** (owner-operated, real sensor, MOCK ledger and MOCK email) | n/a | Run 12 at 1ff616b: all steps OK, `ownerConfirmed` on every gate, verifier ok (`p0-4-laptop-run12.md`) | n/a | Owner confirmed full text and bold amount |
| P1.5 | Vault risk context from an independent authenticated source | **NOT_RUN** | n/a | n/a | n/a | n/a |
| P1.6 | Unauthenticated login flood exhausting console memory | **MITIGATED** | `p1-6-login-flood.txt` (failing) | pass | P1.6 mutants 2/2 | sound |
| P1.6o | Issuer quotas; notification floods beyond the existing V5 controls | **NOT_RUN** | n/a | n/a | n/a | n/a |
| P1.7 | Journal tail truncation by someone with write access to the SQLite file | **MITIGATED** (witnesses are an in-process MOCK) | `p1-7-truncation.txt` (3 failing) | pass | P1.7 mutant 1/1 | sound |
| P1.8 | DNS rebinding against the loopback Owner Console | **MITIGATED** | `p1-8-loopback.txt` (foreign Host served 200) | 421 for foreign or missing Host | P1.8 mutants 2/2 | sound |
| P1.8f | Console input fuzzing (1500 requests, seed 1414, with and without session) | **MITIGATED** (clean before the change; kept as a regression test) | passed before the change | pass | n/a | sound |
| P1.8m | Public MCP payment tools | unchanged: still disabled | n/a | n/a | n/a | n/a |
| P1.9 | Supply chain: lockfiles, secret scan, SBOM | **MITIGATED** (local checks only) | n/a for the new check; the review's false negatives (PEM as string literals, legacy-encrypted/DSA/PGP, JWK) reproduced in `p1-9-review-prefix.txt` | `supply-chain/report.json`: 2 lockfiles v3 with integrity hashes and exact pins, 0 secret findings, CycloneDX SBOMs for both lockfiles (68 + 98 components) | P1.9 mutants 2/2 | no leak of values; LOWs fixed in f80e6ac |
| P1.9a | npm audit / advisory database; build provenance | **NOT_RUN** (no network or CI runner for this) | n/a | n/a | n/a | n/a |
| P1.9t | Tenant isolation, configuration hardening | **NOT_RUN** | n/a | n/a | n/a | n/a |
| P2.10 | New OS isolation work | **NOT_RUN** (the existing v2-os-isolation CI job still runs) | n/a | n/a | n/a | n/a |
| P2.11 | NEAR Testnet | **NOT_RUN** (needs explicit authorization) | n/a | n/a | n/a | n/a |
| P2.12 | CI matrix Linux plus Windows | Linux CI: GitHub Actions `SafeBox CI` on every push (Node 22/24, contract, os-isolation). Windows: **NOT_RUN** as CI; Windows tests ran locally on the laptop only and are not labelled CI | n/a | n/a | n/a | n/a |

## 2. Per-item detail

### P0.1: same-user signing with the fingerprint-gate key

- **Threat model.** Malware running as the owner's Windows user, without admin, calls CNG on the gate key.
- **Reproducer.** On the real laptop: TPM provider, `uiProtectionLevel None`, `signedWithoutFingerprint: true`, process not elevated. The confirmed attack is that **same-user signing works**.
- **Fix.**
  - The gate signature never stands alone. A payment still needs the owner's own WebAuthn UV assertion for passkeys, so LOCAL_GATE degrades to Windows Hello UV, not to nothing.
  - For ed25519 device credentials the bound is device possession only, and the docs say so plainly.
  - `fingerprintAssurance: HIGH_ASSURANCE` is owner-signed at genesis and optional (default LOCAL_GATE, digest unchanged). It fails closed at Root, Vault, verifier, device and console gate, because `ISOLATED_GATE_KINDS` is empty: no isolated gate exists yet.
  - Fingerprint-only credentials always need their V6 approval, including under LEGACY_V5, in both the pre-check and the payment transaction.
- **Remaining exposure.** Under LOCAL_GATE, same-user malware that also gets a UV assertion (or holds an ed25519 device key) can approve. Bounded by the existing spending limits and the FIXED_600 buffer, both unchanged.
- **Trade-off.** HIGH_ASSURANCE currently makes fingerprint-only unusable. That is intentional: no unsupported hardware claim is made.
- **Next step.** An independent signer (separate service account, TPM key with a UI policy, or an external authenticator), then add its kind to `ISOLATED_GATE_KINDS`. Details are in `P0-1-SAME-USER-SIGNING.md`.

### P0.2: compromised console

- **Threat model.** A console page or process that shows the owner one command and asks the gate to sign another, or forges the payment summary.
- **Fix.**
  - The device rebuilds every command from its own Root replica (`reviewPrepared`). It checks the grant against the Root-pinned issuer and refuses any mismatch or digest-only request before any fingerprint prompt.
  - The gate window shows the rebuilt text.
  - The Vault recomputes `summaryDigest` (`V6_SUMMARY_NOT_CANONICAL`).
  - Free text is reduced to printable ASCII with '|' neutralised, so it cannot add, remove or shift a window line.
  - The amount is shown in bold, but only from the fixed PAYMENT line.
- **Remaining exposure.**
  - UV-only credentials on the console route (INHERENT_RESIDUAL).
  - The reviewer runs in the runner process, so OS isolation (P2.10) is still needed.
  - No trusted display (BLOCKED_OPERATOR_HARDWARE).

### P0.3: nonce, commit, concurrency, crash recovery, idempotency

- **Reproducer.** A crash right after the commit left the challenge reusable, or a payment without evidence. Two interleaved workers could admit two payments. A crash at each write inside the proposal produced partial records.
- **Fix.** The challenge nonce and the approval evidence are written inside the same `BEGIN IMMEDIATE` payment transaction, with a PRIMARY KEY on the nonce.
- **Fault injection.** A crash at every write either leaves nothing or leaves the complete record.
- **Remaining exposure.** None known in scope.

### P0.4: real-device re-test

- Run 11 at 9621e99 and run 12 at 1ff616b (the final helper, SHA-256 `D4AC85CA…5DFE`) both passed.
- Run 12 covered PAYMENT, then MOCK settlement after the 10-minute buffer, then FREEZE (with a new payment refused, `FREEZE_ACTIVE`), then the independent verifier ok, then HOLD_RELEASE.
- The owner confirmed that each window showed the full context and the bold amount.
- Raw evidence stays on the laptop: `D:\APORIA\safebox-v6-laptop-runs\hardening-run12`.
- This is local, owner-operated evidence. It is not hardware assurance against same-user malware (see P0.1).

### P1.6, P1.7, P1.8, P1.9 (mitigations)

- **P1.6.**
  - Pending logins are capped at 1024, oldest dropped first, and the audit log is capped at 5000 with a dropped-count.
  - Residual: a burst of more than 1024 starts between the owner's start and finish evicts the owner's login. This fails closed, and the owner retries.
- **P1.7.**
  - Owner approvals, freezes, holds, revocations, incidents, delegation and rapid-use events are checkpointed immediately to the witnesses.
  - Bound: at most `checkpointEvery − 1` non-critical events after the newest checkpoint can vanish undetected. These include PAYMENT_PROPOSED of a delegated payment.
  - The witnesses are an in-process MOCK, so external anchoring is not done.
- **P1.8.**
  - Requests with a foreign or missing Host get 421 before routing. The console's own host, its loopback alias and the bound port are allowed.
  - CSRF and Origin checks were already in place, and the fuzz found nothing before or after the change.
- **P1.9.** Offline script `scripts/v6/supply-chain.mjs`. It never prints matched secret values. It is not a substitute for gitleaks or npm audit.

## 3. Exact test outcomes (code at f80e6ac)

| Suite | Result | Baseline at bf7403d |
|---|---|---|
| `npm test` (root) | **571/571** | 527/527 |
| `node --test tests/v6/*.test.mjs` | **95/95** | 51/51 |
| `integrations/external-interactor` `npm test` | **40/40** (at 2106493; interactor code unchanged since) | 40/40 |
| Showcase (MOCK, `--no-video`) | **11/11 clips** (at 2106493, `docs/evidence/v6/showcase/2026-11-14T1428Z-mock`) | 11/11 |
| Mutations (full run plus P1.9 pair) | **74/76 caught**, 0 pattern errors (`mutations-full-final.json`). Two device mutants with stale anchors were dropped as duplicates of the P0.2 mutants (re-run caught: `mutations-reanchor-device.json`) | 48/48 |
| Windows-only tests on the laptop at 1ff616b | 15/16. The one failure was a test path bug (`URL.pathname`), fixed in 2106493; not re-run on Windows since | 13/13 at 9e230d2 |
| GitHub Actions `SafeBox CI` (Linux only) | runs on every push; see the PR checks | n/a |

All old baselines are preserved: no previous test was deleted or weakened, and old evidence is untouched.

## 4. Mutation survivors (2)

- `Vault: V6 challenge nonce single-use removed` (pre-check)
- `P0.3: in-transaction challenge check removed`

Each is redundant behind the nonce PRIMARY KEY, which refuses the second insert inside the same transaction. The HO mutant that removes all three is caught by 3 tests. This is defence in depth, not a gap.

## 5. Unresolved risks and release blockers

**Release blockers (before any real-money use).**
1. No independent signer: fingerprint-only is LOCAL_GATE only (P0.1d).
2. No OS isolation between the runner/reviewer and same-user processes (P2.10).
3. Journal witnesses are a MOCK: there is no external anchoring (P1.7).
4. No Windows CI. No npm audit or provenance (P2.12, P1.9a).
5. P1.5 independent risk context, and tenant isolation, NOT_RUN.
6. NEAR Testnet run not authorized (P2.11).

**Inherent residuals (kept, by design).**
- Stolen in-Purpose PAY credential.
- Malicious holds.
- Compromised OS.
- UV-only console route.
- LOCAL_GATE same-user signing within limits.

EXP_30 stays rejected, and FIXED_600 and spending limits are unchanged.

## 6. Independent review

| Round | Commit | Verdict |
|---|---|---|
| 1 | 9e230d2 | P0.3 CONFIRMED; P0.2 and P0.1 CONFIRMED_WITH_ISSUES (1 MEDIUM, 2 LOW). All fixed. |
| 2 | 7df30d7 | All FIXED; 1 new LOW (logging attribution), fixed in 66eb97f |
| 3 | 1569fc6 | Gate and tree PASS_WITH_ISSUES (2 MEDIUM, 3 LOW), fixed in ee18ad1 |
| 4 | ee18ad1 | 1, 3, 4 FIXED; 2 and 5 PARTIAL, follow-ups in fff3f8d; P1.7 and P1.8 sound |
| 5 (final delta) | 2106493 | **PASS_WITH_ISSUES**: items 2 and 5 FIXED, no new HIGH or MEDIUM. LOWs: secret-scan false negatives and interactor SBOM (fixed in f80e6ac); duplicate device mutants (dropped); P1.6 login eviction by a local flood (already the documented residual) |

Final verdict: **PASS_WITH_ISSUES, no open HIGH or MEDIUM.** The f80e6ac LOW fixes were not re-reviewed; they come with a pre-fix reproducer, post-fix tests and 2/2 mutants.

## 7. Test manifest (new in this program)

`tests/v6/`:

| Test file | Tests |
|---|---|
| hardening-p0-gatekey | 11 |
| hardening-p0-console | 5 |
| hardening-p0-summary | n/a |
| hardening-p0-nonce | n/a |
| hardening-p0-gate-display | 3 |
| hardening-p1-review-verifier | 3 |
| hardening-p1-loopback | 2 |
| hardening-p1-journal | 3 |
| hardening-p1-availability | 3 |
| hardening-p1-supply-chain | 3 |

`winbio-gate.test.mjs` also gained the DISOWNED, STALE and CANCELLED cases.

Scripts: `scripts/v6/mutations.mjs` (extended), `scripts/v6/supply-chain.mjs`. Evidence lives in `docs/evidence/v6-hardening/`.
