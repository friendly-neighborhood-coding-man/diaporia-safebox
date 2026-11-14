# Combined verification rerun: V5.1 6586a14 (PR #10) + Interactor 6f8aec7 (after independent-verifier fixes)

Disposable worktree, local merge a21ece2 (parents 6586a14, 6f8aec7; clean, not pushed). The first run on 8acda53 is
kept unchanged in `../combined-v51-6586a14/`.

| Step | Result |
|---|---|
| root `npm ci` / `npm test` (V1–V5.1) | exit 0 / 476/476 |
| package `npm ci` / `typecheck` / `build` | exit 0 / 0 / 0 |
| package `npm test` | 36/36 |
| package `npm run demo` | LOCAL_MOCK_E2E_PASS |
| root `npm test` with the package built | 476/476 |
| `scripts/v5/mutations.mjs` | 48/48 first-order, 4/4 higher-order; tree clean afterwards |

Independent verifier (one pass, on the 8acda53 combined tree): ACCEPT WITH CHANGES; F1 (medium, recovery vs in-flight
PROPOSE), F2/F3 (low) and the memo label break-out are fixed in 88ccbc5 with regression tests; other residuals are listed
in docs/integrations/EXTERNAL_INTERACTOR.md.
