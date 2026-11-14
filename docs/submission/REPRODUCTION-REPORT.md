# Reproduction report: NEAR HACKATHON 2026 submission

Run on 2026-11-14 between 21:10Z and 21:35Z from a **fresh clone of the public GitHub repository**, checked out at the
frozen code commit `a8ce01840d79166403aec159c8c05e70bd916721`, in `/opt/sbx-clean` (world-readable).

Environment: Linux 6.18 cloud container, running as root, Node.js v22.23.4, npm 10.9.9, rustc/cargo from rustup,
Playwright and Chromium preinstalled globally (not from this repository), ffmpeg available. MOCK only: no NEAR RPC,
no accounts, no keys, no email. `git status --porcelain --ignored` after all steps showed only build output
(`node_modules/`, `dist/`, `contract*/target/`); no tracked file changed and no secret file (such as `.demo-bridge-url`)
was left behind.

| # | Command (repo root unless noted) | Exit | Time | Observed |
|---|---|---|---|---|
| 1 | `npm ci` | 0 | 1 s | 68 packages, `found 0 vulnerabilities` |
| 2 | `npm test` | 0 | 39 s | `# tests 586`, `# pass 586`, `# fail 0` |
| 3 | `npm run demo` | 0 | <1 s | `EXECUTED MOCK_EXECUTED`, `REPLAY_BLOCKED NOT_APPROVED_OR_ALREADY_USED`, `MOCK_EFFECTS 1` |
| 4 | `npm run demo:v1` | 0 | 1 s | `send_tx timed out -> reconciled to CONFIRMED via tx status`, `BALANCES {"merchant":"1500000000000000000000000","attacker":"0","effects":2}`, journal `ok:true`, `NOTE: SIMULATED chain. No NEAR testnet transaction was sent.` |
| 5 | `node demo/testnet-v1.mjs` | **2** (expected) | <1 s | `UNVERIFIED: NEAR testnet demo not run. Missing prerequisites: SAFEBOX_CONFIG, ...`, `No transaction was signed or sent.` |
| 6 | `npm ci && npm run typecheck && npm test` in `integrations/external-interactor` | 0 | 13 s | 98 packages, `found 0 vulnerabilities`; `# tests 40`, `# pass 40`, `# fail 0` |
| 7 | `npm run demo` in `integrations/external-interactor` | 0 | 3 s | MCP E2E: `"ledgerStatus": "SETTLED"`, `"merchantCredited": "30000000000000000000000"`, `notVerified`: real MCP hosts, real WebAuthn hardware / OS isolation, NEAR testnet or mainnet |
| 8 | `node scripts/v6/showcase.mjs --out /tmp/sbx-showcase` | 0 | 69 s | `11/11 clips passed`, 11 MP4 clips + traces + SHA256SUMS |
| 8b | `node scripts/v6/showcase.mjs --no-video --out /tmp/sbx-nv` with `NODE_PATH` unset (Playwright not resolvable) | 0 | <1 min | `11/11 clips passed` |
| 9 | `node scripts/v6/real-device-selftest.mjs 47790 /tmp/sbx-st-demo --attack-denials --demo` | 0 | 6 s | 8/8 attacks `refused`, `FREEZE_ACTIVE`, `settledWhileFrozen 0`, `verifierOk true`, recovery ok, `demo mode: bridge secret absent from the terminal output`, 7 bridge approvals |
| 10 | `node scripts/v6/real-device-selftest.mjs 47791 /tmp/sbx-st-default` | 0 | 7 s | Workflow A settled (MOCK), FREEZE, `FREEZE_ACTIVE`, 0 settled while frozen, verifier ok, `HOLD_RELEASE: accepted` |
| 11 | `cargo test --manifest-path contract/Cargo.toml` | 0 | 59 s | `test result: ok. 5 passed` |
| 12 | `cargo test --manifest-path contract-v3/Cargo.toml` | 0 | 45 s | `test result: ok. 24 passed` |
| 13 | `cargo test --manifest-path contract-v4/Cargo.toml` | 0 | 50 s | `test result: ok. 34 passed` |

## Environmental limitations found

1. **OS-principal tests need root and a world-readable checkout.** A first run of `npm test` from a private (0700)
   directory gave 583/586: `OS: access matrix + all 24 techniques`, `OS: containment + automated repair drill` (V2) and
   `OS: V3 principal privilege matrix` failed with `ENOENT .../run.json` and `Cannot find module .../os-probe.mjs`,
   because the unprivileged test users cannot read the checkout. From `/opt/sbx-clean` all 586 pass. These tests create
   local Linux users; they are V2/V3 research tests, not V6 isolation.
2. **Playwright is not declared in `package.json`.** The runner selftest (rows 9, 10) and showcase video mode (row 8)
   used a globally preinstalled Playwright. On a machine without it, install it first
   (`npm install --no-save playwright && npx playwright install chromium`) or use `showcase.mjs --no-video` (row 8b).
3. **Rust crates are downloaded on first `cargo test`** (crates.io access needed). `cargo build --target
   wasm32-unknown-unknown` was not re-run here; it runs in GitHub CI.
4. **Selftest labels.** The selftest `summary.json` labels read `REAL DEVICE AUTH (Windows Hello WebAuthn)` and
   `FINGERPRINT ONLY NOT PROVEN` even though Chromium's virtual authenticator answered; the selftest script itself states
   that its output is SIMULATED DEVICE evidence. Treat rows 9 and 10 as simulated.
5. **Command typo in the evidence index.** `docs/v6/final-candidate/EVIDENCE-INDEX.md` rows 13 and 14 give the selftest
   command as `node scripts/v6/real-device.mjs --selftest ...`. That form starts the real runner and waits for a person
   at a browser. The working command is `node scripts/v6/real-device-selftest.mjs <port> <outdir> [flags]` (rows 9, 10
   above; the same command is in `docs/v6/OPERATOR-GUIDE.md` and the round 2 review). The frozen evidence index is left
   unchanged.
6. **Not reproducible here:** the Windows real-device run (needs the owner, a fingerprint sensor and Windows), real Gmail,
   any NEAR network, Windows CI.

Logs of this run are not committed; they contain only the output quoted above.
