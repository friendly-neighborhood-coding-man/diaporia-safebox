# SafeBox V6 submission video: storyboard and reproducible recording runbook

One take, one execution, one screen recording. **Left half:** the real Owner Console in Microsoft Edge (the device
bridge page, then the Emergency Freeze console). **Right half:** the live terminal of the same run
(`scripts/v6/real-device.mjs`). Every terminal line is an event emitted by that run; nothing is replayed or staged.

Frozen code: `60cfd20` (branch `security-fix/v6-codeql`). Ledger: **MOCK** (no chain, no funds). Email: **MOCK
outbox** for the take (the real Gmail path was verified separately in runs 5/6 and is not needed on screen).

## What the video may and may not say

| Say | Never say |
|---|---|
| "MOCK ledger: the settlement is a simulated ledger receipt" | "transaction on NEAR / on-chain / Testnet / Mainnet" |
| "The owner approved with Windows Hello and the fingerprint gate (WinBio MATCH + gate-key signature)" | "hardware-attested fingerprint", "impossible to bypass" |
| "FINGERPRINT_ONLY_LOCALLY_VERIFIED on this laptop" | "fingerprint-only is proven against same-user malware" (it is not: LOCAL_GATE is an INHERENT_RESIDUAL) |
| "Attack attempts shown are refused at the SafeBox interfaces (attacker side simulated)" | "resists OS / kernel / native-code compromise" |
| "SSTP is a separate partial research result" | anything implying SSTP protects this demo |

## 0. One-time laptop preparation (no owner touch needed)

```
cd /d D:\APORIA
git -C safebox-v6-hardening fetch origin security-fix/v6-codeql
git -C safebox-v6-hardening worktree add ..\safebox-v6-submission 60cfd20
cd safebox-v6-submission
npm ci
cd integrations\external-interactor && npm ci && npm run build && cd ..\..
copy ..\safebox-v6-hardening\tools\winbio-gate\winbio-gate.exe tools\winbio-gate\
certutil -hashfile tools\winbio-gate\winbio-gate.exe SHA256
```
- `tools/winbio-gate/WinBioGate.cs` is unchanged since the run-12 build (1ff616b), so the run-12 helper
  (SHA-256 `D4AC85CAF4DBEB6C6020FA31BEEF2BBFB518A4971E55DD1BD7371B10AE685DFE`) is the right binary. Rebuild with
  the command in OPERATOR-GUIDE.md section 3 if the hash differs, and record the new hash.
- Optional dry run without the owner: `node scripts\v6\real-device-selftest.mjs 47700 ..\safebox-v6-laptop-runs\submission-selftest --attack-denials --demo`
  (Chromium virtual authenticator: SIMULATED DEVICE evidence only).

## 1. Screen and redaction setup (before pressing Record)

- **One display**, OBS **Display Capture** (gdigrab and Windows Graphics Capture of single windows failed earlier).
  1920x1080 or the laptop's native resolution, 30 fps.
- **Left half:** Edge as app windows (no tabs, no profile avatar, no address bar with the account name):
  open the bridge with `msedge --app=<link from .demo-bridge-url>`; later the freeze console the same way.
  If app mode is not used, crop the Edge title/profile bar in OBS (Crop/Pad filter) or use a profile without a picture.
- **Right half:** Windows Terminal (or cmd) with a neutral prompt and title, so no user name or `D:\...` path shows:
  `prompt $G` and `title SafeBox V6 demo` (cmd), then `cls`. Font size 14+.
- Close mail, chat, notifications (Focus assist ON), and anything showing your name or email. Hide the taskbar
  or crop it.
- Windows Hello's own dialog is drawn on the secure desktop and **does not appear in the capture**. Optional: a
  phone or webcam shot of the finger on the sensor as picture-in-picture (OBS Video Capture Device); otherwise the
  edit adds a caption "Windows Hello prompt (not captured by Windows)" at each prompt.
- Nothing secret is printed in `--demo` mode: the per-run bridge link goes to `.demo-bridge-url` (gitignored, 0600) and
  the clipboard; the terminal shows `bridge#t=<per-run secret, redacted>`. The bridge page removes the secret from its own address bar
  as soon as it loads, and the runner deletes `.demo-bridge-url` when it exits. Do not reload the bridge page during the
  take (the secret is no longer in its URL); if you must, open the link from `.demo-bridge-url` again. The freeze link that appears is a
  navigation-only locator (no token, no approval; it needs Windows Hello sign-in) that dies with the run.

## 2. The take

Start OBS recording, then in the right-hand terminal:
```
node scripts\v6\real-device.mjs --helper tools\winbio-gate\winbio-gate.exe --attack-denials --demo --out ..\safebox-v6-laptop-runs\submission-take-01
```
(no `--gmail-creds`: the alert goes to the MOCK outbox; no `--record`: OBS records.)

| # | Scene | Left (Owner Console) | Right (terminal, same run) | Owner action | Edit note |
|---|---|---|---|---|---|
| 1 | Start | empty | `STEP Open the bridge link ... <per-run secret, redacted>` | paste the clipboard link into `msedge --app=` | title card: MOCK LEDGER, real device, labels |
| 2 | Sensor check | bridge "touch the sensor" notice; gate window | `OK WinBio probe`, `OK sensor check 1: MATCH` | Start fingerprint check, touch, Yes | |
| 3 | Enrollment | 6 ENROLL cards | `STEP Enrollment ...`, `OK enrolled: k2-laptop ..., gate key WINBIO_TPM` | Windows Hello x6, gate-key touch | speed up 4x, caption "account genesis, signed on the device" |
| 4 | Owner payment approval | PAYMENT APPROVAL card: exact amount in **bold** (0.03 NEAR, MOCK), recipient, Purpose, expiry | `AI prepare_payment: AWAITING_OWNER_APPROVAL`, `TOUCH ...` | Approve, Windows Hello, Start fingerprint check, touch, Yes | hold 3 s on the bold amount |
| 5 | Result + replay | card shows approved | `OK owner approval -> SUBMITTED_TO_VAULT`, `DENY ATTACK 01 immediate replay ...`, `OK MOCK settlement after the 10-minute buffer: settledVerified=true` | none | caption "10-minute buffer on a mock clock" |
| 6 | Attack denials | bridge idle | `DENY ATTACK 02` ... `DENY ATTACK 06` (out-of-purpose recipient, stolen MCP token, amount/recipient swap, stolen PAY key, gate without/foreign Origin) | none | zoom the terminal; one caption per line |
| 7 | Incident + alert | | `STEP Workflow B ...`, `MAIL alert DELIVERED via MOCK`, `DENY ATTACK 07 6 scanner GET/HEAD ... frozen=false` | none | caption "a link scanner cannot freeze or approve anything" |
| 8 | Emergency FREEZE | open the freeze link (`msedge --app=...`), sign in as `k2-laptop` (Windows Hello), read incident and scope, type `FREEZE EVERYTHING`, approve | `TOUCH ... SafeBox V5 - FREEZE ...`, `OK REAL fingerprint gate MATCH for the console command`, `OK FROZEN by the owner: hold ef-...` | Hello, phrase, touch, Yes | |
| 9 | Blocked payment | console shows FROZEN | `OK new payment while frozen: FREEZE_ACTIVE`, `INFO Vault payment states after 30 min frozen: [SETTLED, FROZEN, ...]`, `OK independent V6 verifier: ok=true` | none | caption "the stolen-key payments stay frozen" |
| 10 | Recovery | HOLD_RELEASE card on the bridge | `STEP Recovery ...`, `OK HOLD_RELEASE: accepted; frozen now false` | Approve, Hello, touch, Yes | |
| 11 | Close | | `DONE evidence: ..\safebox-v6-laptop-runs\submission-take-01` then `type ...\summary.json` (labels incl. `ATTACK DENIALS: 8/8 refused`) | none | end card: claims and non-claims table above |

Expected length: about 6 to 9 minutes raw; 3 to 4 minutes after speeding up enrollment.

## 3. After the take

1. Stop OBS. Keep the raw file on the laptop (`D:\APORIA\safebox-v6-laptop-runs\submission-take-01\`), never upload it unedited.
2. Note which Windows Hello modality you used at each prompt (fingerprint / face / PIN); add it to the run folder as
   `owner-attestation.md`. SafeBox cannot see it.
3. Check `summary.json`: `results.workflowA.settledVerified=true`, `workflowB.paymentWhileFrozen=FREEZE_ACTIVE`,
   `settledWhileFrozen=0`, `verifierOk=true`, `recovery.ok=true`, `attacks` all `refused: true`, labels include
   `FINGERPRINT_ONLY_LOCALLY_VERIFIED`. `git` must equal `60cfd20`.
4. Redaction pass on the edited video: no email address, no user name, no `C:\Users\...`/`D:\...` paths, no tokens,
   no bridge link. Blur anything missed.
5. Record `certutil -hashfile <final.mp4> SHA256` in the run folder next to `SHA256SUMS`.

## 4. Fallback if something fails during the take

- Sensor or gate failure: the runner fails closed to a labelled UV-only run (`FINGERPRINT ONLY NOT PROVEN`). Stop,
  do not publish that take as fingerprint evidence; start a new take with a new `--out` folder.
- Bridge never connects (10 min) or the owner does not freeze within 15 min: the runner exits/records the failure.
  Start a new take.
- The MOCK showcase (`node scripts\v6\showcase.mjs`, 11 clips, SIMULATED DEVICE) is the backup video; it must be
  labelled SIMULATED DEVICE everywhere it is shown.
