# SafeBox V6 final report: READY_FOR_OPERATOR_REVIEW

- Branch: `claude/project-thread-xfzte9`
- Draft PR: #13 (never merge). Frozen PRs #9 and #10 are untouched.
- Ledger: always MOCK. No real funds, no NEAR Testnet or Mainnet.

## Status, item by item

| Item | Status | Evidence |
|---|---|---|
| Implementation complete | **YES** | `src/v6/**`, `scripts/v6/**`, `tools/winbio-gate/`; docs `docs/v6/` |
| Simulated E2E verified | **YES** | root regression 527/527; `tests/v6` 51/51; interactor 40/40; mutations 48/48; mock showcase 11/11 clips |
| Actual Gmail delivered | **YES, owner-attested** | 4 real alerts, each `GMAIL_API_ACCEPTED`, token scope exactly `gmail.send`. Inbox receipt confirmed by Eric for the 10:29Z, run 5 and run 6 alerts. Only recipient: the one he approved. |
| Real Windows Hello (WebAuthn UV) | **YES** | Runs 5 and 6 on the owner's laptop: passkey enrollment, payment approval, console sign-in, FREEZE, HOLD_RELEASE |
| Fingerprint-only verified | **LOCALLY VERIFIED on the final gate build cb60433 (PAYMENT only), not hardware-attested** | Run 9: Start click, fresh touch and owner "Yes" approve; PAYMENT settled (WinBio MATCH, TPM key `WINBIO_TPM`). Run 10: Start click, hands off: gate `BIOMETRIC_TIMEOUT`, refused before the Windows Hello payment prompt was even shown (so no PIN could help), nothing reached the Vault. Runs 7 and 8 showed that the earlier gate builds (incl. the one used in run 6) could MATCH without a deliberate touch, so the run 6 gated FREEZE / HOLD_RELEASE are **not** counted as fingerprint-only proof. FREEZE and HOLD_RELEASE were not re-run on cb60433. |
| Real video recorded | **YES (OBS, owner's screen)** | Run 5 and run 6 MP4s with SHA-256 in the laptop evidence folders. Not committed: they show the inbox, a name and this chat. |
| Independent review passed | **NO: first verdict FAIL; fixes re-verified**. The gate-freshness changes (5af5f85..623d234) were tested on the real device but not independently reviewed. | See below |

## Real-device runs (owner's laptop, `D:\APORIA\safebox-v6\docs\evidence\v6\real-device\`)

| Run | Outcome |
|---|---|
| 1 (1035Z) | Stopped. The fingerprint helper had no window, so WinBio system-pool focus never delivered the touch. Fixed: a focused window. |
| 2 (1056Z) | Stopped at Root genesis, `ENROLLMENT_SYNCABLE_PASSKEY_UNDECLARED`. Chrome saved the passkey to Google Password Manager. Correct fail-closed behaviour. |
| 3 | Cancelled on purpose: the review found the bridge showed the wrong text during the payment. |
| 4 | Owner cancelled the passkey prompt, and the run ended. Fixed: cancelled prompts are now retryable. |
| 5 (1110Z) | **Complete, UV-only.** The sensor check misread "finger unknown" as unsupported (mapping bug, fixed). The live syncable-passkey refusal worked. Real Gmail alert, then the link, then FREEZE, payment refused with `FREEZE_ACTIVE`, 0 settled while frozen, verifier ok, HOLD_RELEASE. |
| 6 (1117Z) | **Complete, fingerprint gate armed.** Real Windows Hello plus the WinBio gate (TPM key) on PAYMENT, FREEZE and HOLD_RELEASE. Real Gmail alert opened from the inbox. 0 settled while frozen, verifier ok. The `summary.json` labels came from a static rule (fixed in 1075ca3); the corrected labels are in `labels-correction.json`. |
| 7 (1124Z, 1075ca3) | **Defect found.** PIN-only check: the PAYMENT gate window reported a WinBio MATCH ~6 s after it opened. The owner states he did not touch the sensor (OBS shows no Windows Hello dialog during the gate). Payment settled. Fingerprint-only downgraded. |
| 8 (1146Z, bff0a2c: click-to-start) | **Defect persists.** Start was clicked; MATCH 2.3 s into capture; owner reports no touch. Payment settled. |
| D1 diagnostics | New build 613e093: a real touch then an immediate hands-off window timed out. Old build bff0a2c: the same sequence gave a MATCH, but the owner is not sure his hands were off (INCONCLUSIVE). The Windows Biometrics event log does not map 1:1 to helper results, so it proves neither a stray touch nor a replay. Root cause UNRESOLVED (stray contact with the power-button sensor vs a queued sample). |
| 8b (1200Z, 613e093: + 3 s quiet phase) | **Refused as intended.** Start, hands off: `BIOMETRIC_TIMEOUT`, nothing sent to the Vault. |
| 9 (1216Z, cb60433: + post-MATCH Yes/No) | **Approved as intended.** Sensor check, gate-key enrollment and PAYMENT each: Start, fresh touch (1.1 to 3.5 s capture, 0 discards), Yes. PAYMENT settled (MOCK), label FINGERPRINT_ONLY_LOCALLY_VERIFIED for 1 gated approval. |
| 10 (1219Z, cb60433) | **Refused as intended.** Start, hands off: gate `BIOMETRIC_TIMEOUT`; the Windows Hello payment prompt never appeared; nothing reached the Vault. The "No, I did not touch it" path was not exercised (no stray reading occurred). |

Gate helper fixes during the series: 5af5f85 (click-to-start, discard captures under 700 ms, diagnostics), 9753d36 (mouse only, keystrokes cannot arm), 148fce1 and 6318362 (timing and crash fixes), bff0a2c (separate capture window), 613e093 (3 s quiet phase), cb60433 (post-MATCH owner confirmation; "No" gives `BIOMETRIC_TOUCH_DISOWNED`), 623d234 (log `ownerConfirmed`; runs 9/10 used the cb60433 wrapper, so their gate log lacks the field, while the helper signs only after Yes). 1207Z and 1208Z are aborted run folders (operator error / no owner connection), labelled ABORTED. OBS recordings for runs 7, 8 and 8b/9/10 are on the laptop with SHA-256 in the run folders; not committed.

In runs 5 and 6, the AI client's post-buffer MCP status read failed, a harness reconnect issue. Settlement was confirmed from the Vault state (SETTLED) instead. Fixed in ed953e6 and 1075ca3.

## Independent review

A fresh agent attacked the code from scratch.

**First verdict: FAIL.** The Root, Vault and verifier core held: binding, Root-pinned challenge, durable nonce, gate checks, Gmail scope and the loopback RP.

Re-verification at 869fd4c and later:

| Finding | Severity | Status |
|---|---|---|
| Bridge showed ENROLL text while the payment was signed | HIGH | **FIXED** |
| Any local process could answer bridge WebAuthn requests | HIGH | **FIXED**: per-run secret in the URL fragment, Host check |
| Console page signs the server-supplied challenge | MED | **PARTIAL**. Login now uses a device-derived challenge. The FREEZE step still signs what the console prepared, and the console serves its own page. A compromised console in the owner's own runner process is a residual (it holds the challenge issuer too). |
| Gate server would sign for any local process | MED | **FIXED after re-review** (eb493fb): it signs only a digest the console holds as PREPARED. Not re-reviewed. |
| RSA public exponent e=1 accepted | LOW | **FIXED** |
| Direct (non-emergency) FREEZE needs no incident | LOW | **By design**: an owner-signed ordinary freeze |
| `summaryDigest` not recomputed | LOW | **OPEN**: display-only field |
| Gate key is a plain per-user CNG key (no UI protection) | MED | **OPEN residual**: same-user malware can sign without a finger |
| Nonce row written after the payment commit | LOW | **OPEN**: a crash in between is flagged by the verifier |

## Risks

See `docs/v6/SECURITY-EVALUATION.md` §7. The main ones:

- The fingerprint gate is local, not hardware-attested. It accepts any finger enrolled under the owner's Windows account.
- Gate freshness: the cause of the run 7/8 unwanted MATCHes is unresolved. The final build counters both explanations (quiet phase, post-MATCH confirmation), but a stray touch followed by a careless "Yes" would still approve.
- Windows Hello UV may be a PIN or a face.
- Same-user malware on the laptop.
- The loopback RP exception (V3 change).
- Gmail acceptance is not proof of inbox delivery.
- No CI runner.
