# SafeBox V6 final candidate: owner recording runbook (Video B, real device)

**Frozen code: `a8ce01840d79166403aec159c8c05e70bd916721`** (branch `integration/v6-final-candidate`). This replaces the
`60cfd20` runbook (docs/v6/submission/VIDEO-STORYBOARD.md on PR #26): `60cfd20` carries the Root dispatch HIGH and the
HOLD_EXPIRE/RAPID_USE_EXPIRE MEDIUM, so do not record on it. Ledger: **MOCK**. Email: **MOCK outbox**. One take, one
execution: the left half is the real Owner Console in Edge and the right half is the live terminal of the same run. Nothing
on screen is replayed or staged. The attacker side is **simulated** and labelled that way.

## What the video may and may not say (unchanged, plus one line)

| Say | Never say |
|---|---|
| "MOCK ledger: the settlement is a simulated ledger receipt" | "on-chain", "NEAR Testnet/Mainnet", "real funds" |
| "Approved with Windows Hello and the fingerprint gate (WinBio MATCH + gate-key signature)" | "hardware-attested fingerprint", "impossible to bypass", "hardware-isolated signing" |
| "FINGERPRINT_ONLY_LOCALLY_VERIFIED on this laptop" | "fingerprint-only is proven against same-user malware" (LOCAL_GATE same-user signing is an INHERENT_RESIDUAL) |
| "Attack attempts are refused at the SafeBox interfaces; the attacker side is simulated" | "resists OS, kernel or native-code compromise" |
| "Email links are navigation only; they authorize nothing" | "the email link approves/freezes" |
| "SSTP is separate partial research" | anything implying SSTP protects this demo |

## 0. One-time laptop preparation (no owner touch)

```
cd /d D:\APORIA
git -C safebox-v6-hardening fetch origin integration/v6-final-candidate
git -C safebox-v6-hardening worktree add ..\safebox-v6-final a8ce01840d79166403aec159c8c05e70bd916721
cd safebox-v6-final
git rev-parse HEAD
npm ci
cd integrations\external-interactor && npm ci && npm run build && cd ..\..
copy ..\safebox-v6-hardening\tools\winbio-gate\winbio-gate.exe tools\winbio-gate\
certutil -hashfile tools\winbio-gate\winbio-gate.exe SHA256
```
- `git rev-parse HEAD` must print `a8ce01840d79166403aec159c8c05e70bd916721`.
- The interactor **must be built** (`npm run build`) in a fresh worktree, or the runner fails with `ERR_MODULE_NOT_FOUND`.
- `tools/winbio-gate/WinBioGate.cs` is unchanged between `1ff616b` (run 12) and `a8ce018`, so the run-12 helper
  (SHA-256 `D4AC85CAF4DBEB6C6020FA31BEEF2BBFB518A4971E55DD1BD7371B10AE685DFE`) is the right binary. If the hash differs,
  rebuild per OPERATOR-GUIDE.md section 3 and record the new hash.
- Dry run without the owner (SIMULATED DEVICE evidence only):
  `node scripts\v6\real-device-selftest.mjs 47700 ..\safebox-v6-laptop-runs\final-selftest --attack-denials --demo`

## 1. Screen and secret handling (before recording)

- OBS **Display Capture**, one display, native resolution, 30 fps. Focus assist ON; close mail and chat; hide or crop
  the taskbar. Terminal: `prompt $G`, `title SafeBox V6 demo`, `cls`, font 14+.
- Windows Hello's dialog is drawn on the secure desktop and does **not** appear in the capture. Caption it in the edit,
  or add a phone/webcam picture-in-picture of the sensor.
- **Bridge secret (reviewed for on-screen disclosure).** With `--demo` the terminal prints only
  `bridge#t=<per-run secret, redacted>`. The full link goes to `.demo-bridge-url` (0600, gitignored, deleted when the
  runner exits). The clipboard is **not** used unless you pass `--clipboard`. Clipboard history and cloud clipboard sync
  can keep a copy, so do not pass it.
  - **Preferred: `--open-edge`.** The runner itself asks Edge to open the bridge in an `--app` window (no address bar),
    so the secret is never typed, pasted or shown. **Status: NOT_RUN on Windows at freeze time.** Known exposure: the
    secret is on the `cmd`/`msedge` command line. Same-user processes can read it, which is inside the documented
    same-user residual. It can also persist in Windows process-creation audit logs (if enabled) and in Edge history.
    The secret is useless after the run ends, because the bridge server stops.
  - **Fallback**, if no Edge window appears within a few seconds: press **Pause** in OBS, open the link from
    `.demo-bridge-url` without displaying it, then **Resume**. In PowerShell:
    `Start-Process msedge -ArgumentList ('--app=' + (Get-Content .demo-bridge-url))`.
    Never `type`/`cat` the file in the recorded terminal.
  - Do not reload the bridge page during the take. The page removes the secret from its own URL when it loads.
- The Emergency Freeze link printed later (`/e/l<hex>`) is a navigation-only locator. It holds no token and authorizes
  nothing (Windows Hello sign-in is still required), and it dies with the run. Showing it is acceptable. Open it with
  `msedge --app=<that link>`.

## 2. The take

Start OBS recording, then in the right-hand terminal:
```
node scripts\v6\real-device.mjs --helper tools\winbio-gate\winbio-gate.exe --attack-denials --demo --open-edge --out ..\safebox-v6-laptop-runs\final-take-01
```
(No `--gmail-creds`, so the alert goes to the MOCK outbox. No `--record`, because OBS records. No `--clipboard`.)

| # | Scene | Left (Owner Console) | Right (terminal, same run) | Owner action |
|---|---|---|---|---|
| 1 | Start | Edge app window opens (or fallback above) | `STEP Asked Edge to open the bridge ... <per-run secret, redacted>` | snap the window left |
| 2 | Sensor check | gate window | `OK WinBio probe`, `OK sensor check 1: MATCH` | Start, touch, Yes |
| 3 | Enrollment | 6 ENROLL cards | `OK enrolled: k2-laptop ..., gate key WINBIO_TPM` | Windows Hello x6, gate-key touch |
| 4 | Payment approval | PAYMENT APPROVAL card, amount in **bold** (0.03 NEAR, MOCK) | `AI prepare_payment: AWAITING_OWNER_APPROVAL` | Approve, Hello, touch, Yes |
| 5 | Result + replay | approved | `DENY ATTACK 01 immediate replay`, `OK MOCK settlement after the 10-minute buffer` | none |
| 6 | Attack denials (SIMULATED attacker) | idle | `DENY ATTACK 02` ... `06` | none |
| 7 | Incident + alert | | `MAIL alert DELIVERED via MOCK`, `DENY ATTACK 07 ... frozen=false` | none |
| 8 | Emergency FREEZE | freeze console: sign in as `k2-laptop`, type `FREEZE EVERYTHING`, approve | `OK REAL fingerprint gate MATCH ...`, `OK FROZEN by the owner` | Hello, phrase, touch, Yes |
| 9 | Blocked payment | FROZEN | `OK new payment while frozen: FREEZE_ACTIVE`, verifier ok | none |
| 10 | Recovery | HOLD_RELEASE card | `OK HOLD_RELEASE: accepted; frozen now false` | Approve, Hello, touch, Yes |
| 11 | Close | | `DONE evidence: ..\safebox-v6-laptop-runs\final-take-01` | none |

The 10-minute buffer is a fixed 600 s on a **mock clock** (the run does not wait 10 real minutes).

## 3. After the take: acceptance checks

In `final-take-01\summary.json`:
- `git` = `a8ce01840d79166403aec159c8c05e70bd916721`
- `results.workflowA.settledVerified = true`
- `workflowB.paymentWhileFrozen = FREEZE_ACTIVE`, `settledWhileFrozen = 0`, `verifierOk = true`
- `recovery.ok = true`
- every `attacks[*].refused = true` (8/8)
- labels include `FINGERPRINT_ONLY_LOCALLY_VERIFIED`. If the label is `FINGERPRINT ONLY NOT PROVEN`, the sensor or gate
  failed closed to UV-only; do not publish that take as fingerprint evidence.

Then add `owner-attestation.md` (which Hello modality you used at each prompt), run a redaction pass (no email, user
name, `C:\Users\...` / `D:\...` paths, tokens or bridge link), and record `certutil -hashfile <final.mp4> SHA256`.

## 4. Fallbacks

- Sensor/gate failure, bridge never connects (10 min), or no freeze within 15 min: the runner fails closed and records
  why. Start a new take with a new `--out`.
- Backup video: `node scripts\v6\showcase.mjs` (11 MOCK clips), labelled **SIMULATED DEVICE** everywhere it is shown.
