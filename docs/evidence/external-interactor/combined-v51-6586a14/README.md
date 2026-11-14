# Combined verification: V5.1 candidate 6586a14 (PR #10) + Interactor candidate 8acda53 (PR #9)

Disposable worktree, local merge commit 8531dc5 (parents 6586a14, 8acda53; clean merge, not pushed anywhere).
Script: `run.sh` (copied here). Logs and exit codes are next to this file. Cloud container, Node 22.23.4.

| Step | Result |
|---|---|
| root `npm ci` | exit 0 |
| root `npm test` (V1–V5.1) | 476/476, exit 0 |
| package `npm ci` / `typecheck` / `build` | exit 0 / 0 / 0 |
| package `npm test` (E2E, OAuth, security) | 33/33, exit 0 |
| package `npm run demo` (mock E2E on V5.1 code) | LOCAL_MOCK_E2E_PASS, exit 0 |
| root `npm test` with the package built | 476/476, exit 0 |
| `scripts/v5/mutations.mjs` -> `v5-mutations.json` | first-order 48/48 caught, higher-order 4/4, exit 0 |
| `git status` after mutations | clean (all mutants restored) |

The adapter does not read V5.1's new `v5_pay.evaluated` column or incident ids. MOCK only; same "not verified" list as
docs/integrations/EXTERNAL_INTERACTOR.md.
