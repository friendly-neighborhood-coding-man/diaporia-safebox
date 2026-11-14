# SafeBox V6: submission README

**Status: READY_FOR_SUBMISSION_REVIEW.** Nothing merged, nothing deployed, no real money, no blockchain transaction.

SafeBox is a wallet-safety layer for AI agents. An external AI (over MCP) may only **prepare** a payment. Only the
owner's enrolled device can approve it, with Windows Hello plus a fingerprint gate, and the approval is bound to the
exact amount, recipient, Purpose and expiry. A Risk Engine raises an incident on suspicious activity, the owner gets an
alert with an Emergency Freeze link that carries no authority, and the owner freezes everything from the Owner Console
with a fresh device signature. While frozen the Vault refuses payments; the owner releases the hold from the device.

## Frozen candidate

| Item | Value |
|---|---|
| Repository | `friendly-neighborhood-coding-man/diaporia-safebox` |
| Frozen code commit | **`60cfd20`** (`60cfd20bbb54ccc774b2c108cc18e0a2c93a5563`) on branch `security-fix/v6-codeql` (Draft PR, never merged) |
| Built on | PR #15 `claude/v6-security-hardening` `8cd505b` (hardening) on PR #13 `bf7403d` (V6) |
| Changes since the last owner-run real-device test (run 12, `1ff616b`) | Gmail credential loading, OAuth token write, terminal sanitizer, new opt-in `--attack-denials` / `--demo` runner flags, scripts and docs. Root, Vault, verifier, fingerprint-gate and helper code unchanged; the only `src/v6/device` change is one line in the bridge page that removes `#t=<secret>` from the address bar (`git diff --stat 1ff616b 60cfd20 -- src tools`) |
| Ledger | **MOCK** only. Amounts are shown in NEAR units but nothing is sent to any chain. A "settlement" is a MOCK ledger receipt. |
| SSTP | Separate, **partial research result** (`experiment/secure-transition-v0`, PR #16; patch `security-fix/sstp-verifyslot`). Not part of this candidate and not a production security guarantee. |

## How to reproduce

Linux (CI-equivalent, no hardware): Node >= 22.13.
```
npm ci && (cd integrations/external-interactor && npm ci && npm run build)
npm test                                                     # root suites
(cd integrations/external-interactor && npm test)            # MCP interactor
node scripts/v6/showcase.mjs --no-video                      # MOCK showcase, 11 clips
FAKE_WINBIO_KEYFILE=/tmp/fake.pem node scripts/v6/real-device-selftest.mjs 47700 /tmp/selftest \
  --helper tests/v6/fixtures/fake-winbio-helper.mjs --attack-denials --demo   # runner plumbing, SIMULATED
```
Owner's Windows laptop (real Windows Hello + fingerprint, owner present): see `VIDEO-STORYBOARD.md` section 0 to 2
and `docs/v6/OPERATOR-GUIDE.md`.

## What is claimed, at what scope

| Claim | Scope / label |
|---|---|
| The AI cannot sign, approve, settle, freeze or touch keys: MCP offers only status, check, prepare | Interface-level, tested (interactor 40/40, showcase clip 01, attack 03) |
| A payment needs a fresh owner approval bound to the exact amount / recipient / Purpose / expiry; substitutions and replays are refused | Tested in code and in the runner's attack phase |
| Fingerprint-only approval on the owner's laptop (WinBio MATCH + gate-key signature + post-MATCH Yes) | **FINGERPRINT_ONLY_LOCALLY_VERIFIED** on run 12 (`1ff616b`); a new owner take on `60cfd20` is pending. Not hardware attestation. |
| Same-user malware on Windows can sign with the gate key | **INHERENT_RESIDUAL** (LOCAL_GATE). HIGH_ASSURANCE fails closed; no isolated signer exists yet (BLOCKED_OPERATOR_HARDWARE). |
| Emergency Freeze from an alert link; the link and the email carry no authority; scanners change nothing | Tested (showcase clips 05/10, attack 07, workflow B) |
| Frozen Vault refuses new payments; release only by the hold issuer's device signature | Tested (workflow B, recovery) |
| Real Gmail alert | Verified earlier (runs 5/6, owner-attested inbox receipt); MOCK outbox in the submission take |
| OS isolation, tenant isolation, NEAR Testnet, Windows CI, advisory-database audit | **NOT_RUN** |

## Documents in this folder

- `CODEQL-TRIAGE.md`: every CodeQL finding with an exploitability verdict and the fix or the reason for no fix.
- `EVIDENCE-INDEX.md`: where each piece of evidence lives and what it proves.
- `VIDEO-STORYBOARD.md`: the split-screen recording (real Owner Console left, live terminal right, same execution).
- `FINAL-VERIFICATION-SUMMARY.md`: exact verification scope, results and unresolved findings.
