# SafeBox V6 operator guide (owner's Windows laptop)

Every command runs from the repository root on the laptop. Nothing in this guide moves real funds: the ledger is always MOCK.

## 1. Setup

```
git checkout claude/project-thread-xfzte9
npm ci
cd integrations\external-interactor && npm ci && npm run build && cd ..\..
npm test                         (root suites)
cd integrations\external-interactor && npm test
```

## 2. Gmail (optional, OFF by default)

Gmail sending needs **all** of the following. If any one is missing, the transport reports `NOT_CONNECTED` and sends nothing.

- `SAFEBOX_ALLOW_REAL_EMAIL=1`
- operator OAuth credentials
- an allowlisted recipient

The only scope requested is `https://www.googleapis.com/auth/gmail.send`. A token that comes back with any other scope is refused (`SCOPE_NOT_MINIMAL`).

```
node scripts\v6\gmail-oauth-setup.mjs --client "<path to your OAuth client JSON>" --sender <sender@gmail.com> --out "%USERPROFILE%\.safebox\gmail-send.json"
```

- The setup opens Google's consent page in your browser. You approve it yourself.
- The token file is written outside the repository. Never commit it, paste it or upload it.
- The client JSON is read only at setup time. Its contents are never printed.

**Delivery labels.** A Gmail API 200 is reported as `GMAIL_API_ACCEPTED` / `INBOX_RECEIPT_NOT_VERIFIED`. Inbox receipt is recorded only when the owner says so, as `INBOX_RECEIPT_CONFIRMED (owner-attested)`. The `gmail.send` scope cannot read the mailbox, so receipt can't be checked automatically.

## 3. Fingerprint gate helper (optional)

```
cd tools\winbio-gate
%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /optimize /target:exe /out:winbio-gate.exe /r:System.Core.dll WinBioGate.cs
winbio-gate.exe probe
```

- `probe` only enumerates sensors and opens a system-pool session. It captures nothing.
- `verify-sign` asks the physical sensor through WinBioIdentify. It signs only if the identified Windows account is the current user.
- No sample, template or score ever leaves the helper.

## 4. Mock showcase (simulated device, MOCK ledger)

```
node scripts\v6\showcase.mjs
```

This records 11 clips (main demo plus 10 attacks) with honest labels: SIMULATED DEVICE, MOCK LEDGER, FINGERPRINT ONLY NOT PROVEN.

To add one real alert, use `--real-gmail --gmail-creds <token file> --to <approved recipient>` with `SAFEBOX_ALLOW_REAL_EMAIL=1`. The freeze link in that email only works while the showcase is running.

## 5. Real-device run (owner present)

```
set SAFEBOX_ALLOW_REAL_EMAIL=1        (only if sending a real alert)
node scripts\v6\real-device.mjs --helper tools\winbio-gate\winbio-gate.exe --gmail-creds "%USERPROFILE%\.safebox\gmail-send.json" --to <approved recipient> [--record]
set SAFEBOX_ALLOW_REAL_EMAIL=
```

1. Open `http://localhost:47610/bridge` in Edge or Chrome on the laptop and keep that tab open.
2. Approve each **ENROLL** request with Windows Hello. Each one is a different genesis record, numbered "request k".
3. Touch the sensor when a `TOUCH` line appears.
4. Approve the **PAYMENT** request. The AI prepared it over MCP; the bridge shows the exact recipient, amount, Purpose and expiry.
5. When the alert arrives, open its Emergency Freeze link **on the laptop**. Sign in with Windows Hello, read the incident and scope, type `FREEZE EVERYTHING` and approve.
6. Approve **HOLD_RELEASE** on the bridge page (recovery).

Evidence is written to `docs/evidence/v6/real-device/<stamp>/` (`summary.json`, `trace.jsonl`, `SHA256SUMS`).

- `--record` uses ffmpeg gdigrab. If Windows denies desktop capture (error 5), record with OBS Display Capture instead and add the file to the folder.
- Windows Hello's own dialog may not appear in screen captures.
- Report which modality you used at each prompt (fingerprint, face or PIN). SafeBox cannot see it: Windows Hello UV alone may be a PIN.

`node scripts/v6/real-device-selftest.mjs [port] [outdir]` exercises the same runner with Chromium's virtual authenticator. That output is SIMULATED DEVICE evidence only.

## 6. Mutation testing

```
git worktree add ..\sb-mut HEAD && cd ..\sb-mut && node scripts\v6\mutations.mjs
```

Run it in a separate worktree, because it edits sources in place. Result: `docs/evidence/v6/mutations.json`.
