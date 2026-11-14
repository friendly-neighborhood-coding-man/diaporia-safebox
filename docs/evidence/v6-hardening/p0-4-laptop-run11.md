# P0.4: real-device re-test on the hardened gate build (hardening run 11)

- When: 2026-11-14 ~13:28-13:38Z. Laptop LG 16Z90RU (Goodix MOC sensor in the power button), Edge, Windows Hello.
- Code: hardening branch at **9621e99** (P0.1/P0.2/P0.3 + docs); helper winbio-gate.exe built from WinBioGate.cs at 9e230d2,
  csc no warnings, SHA-256 `F527576567E6A7213562A1453D878DCE34FBDE8B1D1CB1D34A630B076BE67048`. MOCK ledger, MOCK email (no real email sent).
- Evidence on the laptop (not committed; recordings/runs stay on the laptop): `D:\APORIA\safebox-v6-laptop-runs\hardening-run11` (SHA256SUMS, summary.json, trace.jsonl).
- Later commits (9621e99..db3d100: review fixes in the Vault, kit and showcase, plus the bold amount) were NOT part of this run.
  The rebuilt helper at db3d100 (SHA-256 `2A2B65E1DEFA9A081A5B7059E13AD4BDAF4D670C39903A62364C82C5E8EFD83A`, csc no warnings) has not been exercised on the sensor.

## Runner lines (verbatim)
```
OK     bridge page connected
OK     WinBio probe: {"ok":true,"units":1,"systemPoolSession":"OPENED"}
OK     sensor check 1: MATCH (current Windows user)
OK     enrolled: k2-laptop credential rDUvk5lm4oeu…, gate key WINBIO_TPM
OK     owner approval -> {"requestId":"apr_dfd21b8b848beecc21035277206ab0ad","state":"SUBMITTED_TO_VAULT","paymentId":"p_60e64cd8ab904ddeb3a16f084da2a9c6","vaultState":"BUFFERED"}
OK     MOCK settlement after the 10-minute buffer: settledVerified=true
OK     REAL fingerprint gate MATCH for the console command
OK     FROZEN by the owner: hold ef-b17e305abc105fc4 (PROVISIONAL_HOLD)
OK     new payment while frozen: FREEZE_ACTIVE
OK     independent V6 verifier: ok=true, owner approvals=1, emergency freezes=1
OK     HOLD_RELEASE: accepted; frozen now false
DONE   evidence: D:\APORIA\safebox-v6-laptop-runs\hardening-run11
```
No DENY lines. Vault states after 30 min frozen: SETTLED, FROZEN x4.

## Gate log (purpose truncated)
| purpose | ok | ownerConfirmed | elapsedMs | quietDiscards | discarded | armedAfterMs |
|---|---|---|---|---|---|---|
| SENSOR_CHECK | true | true | 1387 | 0 | 0 | 11812 |
| ENROLL_GATE_KEY | true | true | 2101 | 0 | 0 | 8055 |
| SafeBox V6 - PAYMENT APPROVAL … Pay exactly: 30000000000000000000000 yo… | true | true | 3987 | 0 | 0 | 3253 |
| SafeBox V5 - FREEZE … Affects: action:FREEZE … | true | true | 2040 | 0 | 0 | 4792 |
| SafeBox V5 - HOLD_RELEASE … Affects: hold:ef-b17e305… | true | true | 4228 | 0 | 0 | 2603 |

## Result
- PAYMENT, FREEZE (console route through `consoleGate`) and HOLD_RELEASE (device route) each passed with a real WinBio MATCH,
  a post-MATCH "Yes", and the WINBIO_TPM gate key. The owner confirmed (13:35Z, owner-attested) that all three gate windows showed the
  full owner-side command text (P0.2), not a digest.
- Label: **FINGERPRINT_ONLY_LOCALLY_VERIFIED** for PAYMENT, FREEZE and HOLD_RELEASE on this build. This is NOT hardware attestation:
  P0.1 confirmed on this laptop that same-user code can sign with this TPM key without a finger, so fingerprint-only is enforced only
  by the helper. Windows Hello UV: PIN FALLBACK POSSIBLE.
- Owner feature request from this run (bold amount) is in db3d100.
