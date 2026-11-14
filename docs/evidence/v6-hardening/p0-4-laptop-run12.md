# P0.4: real-device re-test on the FINAL gate build (hardening run 12)

- When: 2026-11-14 ~14:08-14:16Z. Laptop LG 16Z90RU (Goodix MOC sensor), Edge, Windows Hello. MOCK ledger, MOCK email.
- Code: **1ff616b** (all P0 fixes, all three independent review rounds' fixes, P1.6-P1.9). Helper built from WinBioGate.cs at 1ff616b,
  csc no warnings, SHA-256 `D4AC85CAF4DBEB6C6020FA31BEEF2BBFB518A4971E55DD1BD7371B10AE685DFE` (500 ms click guard, bold amount
  from the fixed PAYMENT line, '|' neutralisation upstream). Evidence on the laptop only: `D:\APORIA\safebox-v6-laptop-runs\hardening-run12`
  (SHA256SUMS, summary.json, trace.jsonl).
- Local Windows tests at 1ff616b: hardening-p0-gate-display + winbio-gate + hardening-p0-gatekey 15/16. The one failure is a
  test bug on Windows (fixture path via URL.pathname -> "/D:/..."), fixed in the next commit with fileURLToPath; the
  Linux run (and CI) passes.

## Runner lines (verbatim, no DENY)
```
OK     bridge page connected
OK     WinBio probe: {"ok":true,"units":1,"systemPoolSession":"OPENED"}
OK     sensor check 1: MATCH (current Windows user)
OK     enrolled: k2-laptop credential LX7WbFGay8Xe…, gate key WINBIO_TPM
OK     owner approval -> {"requestId":"apr_4cecfe4c015405fc6ab020908a17cb46","state":"SUBMITTED_TO_VAULT","paymentId":"p_aa07fb5a090b4b25801537174fe9de7f","vaultState":"BUFFERED"}
OK     MOCK settlement after the 10-minute buffer: settledVerified=true
OK     REAL fingerprint gate MATCH for the console command
OK     FROZEN by the owner: hold ef-7eae2a9221daf94f (PROVISIONAL_HOLD)
OK     new payment while frozen: FREEZE_ACTIVE
OK     independent V6 verifier: ok=true, owner approvals=1, emergency freezes=1
OK     HOLD_RELEASE: accepted; frozen now false
DONE   evidence: D:\APORIA\safebox-v6-laptop-runs\hardening-run12
```

## Gate log
| purpose | ok | ownerConfirmed | elapsedMs | quietDiscards | discarded | armedAfterMs |
|---|---|---|---|---|---|---|
| SENSOR_CHECK | true | true | 1116 | 0 | 0 | 6831 |
| ENROLL_GATE_KEY | true | true | 1984 | 0 | 0 | 2469 |
| SafeBox V6 - PAYMENT APPROVAL … Pay exactly: 30000000000000000000000 yo… | true | true | 6629 | 0 | 0 | 6340 |
| SafeBox V5 - FREEZE … | true | true | 5118 | 0 | 0 | 2620 |
| SafeBox V5 - HOLD_RELEASE … | true | true | 5297 | 0 | 0 | 3309 |

## Result
PAYMENT, FREEZE (console route) and HOLD_RELEASE (device route) passed on the final build with a real WinBio MATCH, a post-MATCH
"Yes" and the WINBIO_TPM gate key. Owner-attested (Eric, 14:15Z): the payment amount was shown in bold; in run 11 (13:35Z) all
three windows showed the full command text. Label: **FINGERPRINT_ONLY_LOCALLY_VERIFIED** (not hardware attestation; same-user
code can sign with this key, P0.1). Windows Hello UV: PIN FALLBACK POSSIBLE. Real Gmail: NOT RUN in runs 11/12 (MOCK by design).
