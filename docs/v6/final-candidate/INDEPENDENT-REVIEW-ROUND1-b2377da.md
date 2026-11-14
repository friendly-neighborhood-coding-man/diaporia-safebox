# Independent security review: 60cfd20 -> b2377da (SafeBox V6 final candidate)

Reviewer: independent agent, Linux container, Node v22.23.4, running as root. Nothing was pushed and no branch or commit was changed. Worktrees used: <cloud-tmp>/rev (b2377da), <cloud-tmp>/rev0 (60cfd20, baseline), /var/tmp/sbxrev (b2377da, used for OS-isolation tests because <cloud-tmp> is mode 0700). All three were removed afterwards.

## Verdict: PASS_WITH_ISSUES

The diff's own claims check out. Action-name dispatch in V3, V4 (including the V3 passthrough), V5 and V6 (through V5), and V2 technique dispatch, now accept only own properties. Every revert I tried in V3, V4 and V5 is caught by the new tests. The Gmail reconcile adds hardening and does not regress the 60cfd20 descriptor loader. Fingerprint, approval, FREEZE, HOLD_RELEASE and recovery code is untouched.

One confirmed, reachable issue of the same class was missed: inherited object-ID lookups (not action names) in two unauthenticated V5 housekeeping handlers. Through them, anyone who can submit to Root can commit a transition with no approval. The transition advances seq, head, usedNonces and lastAt. It does not change epoch, holds, payments or credentials. The issue already exists at 60cfd20, so this diff did not introduce it.

## Findings

| # | Sev | Location | Evidence | Recommendation |
|---|-----|----------|----------|----------------|
| F1 | MEDIUM | src/v5/root/chain.mjs:280 (`HOLD_EXPIRE`: `s.v5.holds[a.body.holdId]`), :471 (`RAPID_USE_EXPIRE`: `s.v5.rapid.grants[a.body.grantId]`) | These handlers take no evidence (`noEvidenceBut(tr, [])`). With holdId/grantId `constructor` or `toString`, `h` is an inherited Function, `h.status !== 'ACTIVE'`, and the transition commits. Probe on b2377da V6 world (`buildV6`, `w.submit`, no approvals): `HOLD_EXPIRE {"holdId":"constructor"} ok=true seq 0 -> 1 nonces 4 -> 5 headChanged true epoch 1 -> 1`. The same happens for `toString` and for `RAPID_USE_EXPIRE {"grantId":"constructor"}`. The control `holdId:"missing"` gets `HOLD_UNKNOWN`. Effect `[{"type":"HOLD_HOUSEKEEPING"}]` (no holdId). `verifyWorld6` returns `ok true`. Identical on 60cfd20, so the issue is inherited. Reachable by any Root submitter (in-process `w.submit` / Root service). It is not reachable from the MCP interactor, which has no Root submit route. Mitigating: HOLD_EXPIRE on any real released or expired hold is already repeatable without approval by design, so the extra impact is chain advancement when no such hold exists. | Use `Object.hasOwn` (or null-prototype objects / Map) for every `s.v5.holds`, `rapid.grants`, `rapid.requests`, `delegations`, `incidentReviews` lookup keyed by body fields. Add a regression test for `HOLD_EXPIRE`/`RAPID_USE_EXPIRE` with inherited IDs that asserts no seq/head/nonce change. |
| F2 | LOW | src/v5/root/chain.mjs:156 (`holds[b.reinforces]`), :330, :348, :381 (`incidentReviews` / `delegations` / `rapid.requests` "already used" checks); src/v6/emergency/console.mjs:67 (`s.v5.holds[String(b.holdId)]`) | Inherited IDs pass the "exists" check at :156 and console:67, and are wrongly reported "in use" at :330/:348/:381. All of these sit behind authenticated owner approvals or an authenticated console session, and later checks fail closed. I found no commit without approval through them. | Same as F1 (own-property lookup) for consistency. |
| F3 | INFO | src/v3/root/chain.mjs:86, src/v4/root/chain.mjs:72,88-92, src/v6/root/chain.mjs:83-85, console.mjs:145,151,169 (`creds[credId]`, `orcs[credId]`) | Inherited credIds resolve to Object.prototype functions. They fail closed: `status !== 'active'` → APPROVAL_CREDENTIAL_NOT_ACTIVE / LOGIN_CREDENTIAL_NOT_ACTIVE, and the signature verifiers (`edVerifyDigest`, `verifyDigest`) return false on an undefined key (try/catch). In V6 `checkGates`, an inherited credId makes `need` false (orcs['constructor'] is truthy), but that credId can never be a fingerprint-only credential and cannot verify, so no gate bypass. | Optional hardening only. |
| F4 | INFO | src/v4/root/chain.mjs:625 | Removing only `Object.hasOwn(H3, a.type)` from `own3` survives the tests (6/6 pass). This is an equivalent mutant: the `V3_PASSTHROUGH` Set already limits names to real V3 handlers. Removing both guards is caught (3 failures). | None needed. You can note it as an equivalent mutant in the evidence. |
| F5 | LOW | scripts/v6/reconcile-mutations.mjs:31-32 | `caught: fail !== 0`, where `fail` is -1 when no TAP `# fail` line is parsed. A crash, timeout or hang therefore counts as "caught". The O_NONBLOCK (FIFO) mutant shows `failingTests: -1` (detected by hang/timeout, not by an assertion). That is plausible for that mutant, but the script does not tell it apart from an unrelated crash. | Report `-1` as `UNKNOWN/TIMEOUT` separately, or give the FIFO test its own timeout assertion. |
| F6 | LOW | src/v6/notify/gmail.mjs:31,48 | New behaviour on POSIX: a credentials file with any group/other bits is refused (`GMAIL_CREDENTIALS_TOO_PERMISSIVE`). 60cfd20 accepted a 0644 file (verified: `60cfd20 load 0644 OK`). This is intended hardening. The side effect is that a token file read via WSL/drvfs (`/mnt/c/Users/...`, which usually shows 0777) is refused. On native Windows Node (`process.platform === 'win32'`) the mode check and O_NOFOLLOW/O_NONBLOCK are skipped (constants undefined → 0), so the behaviour matches 60cfd20 apart from the new symlink error code mapping. The token file under %USERPROFILE% relies on the profile ACL (a documented residual risk, unchanged). | Make sure the laptop run uses native Windows Node, not WSL, if real Gmail is used. The video uses a mock outbox, so this is not on the recording path. |
| F7 | INFO | src/v6/notify/gmail.mjs:66-89 (writer) | Verified on Linux: new file mode 600, also under `umask 0` (600). An existing file or dangling symlink is refused (`GMAIL_CREDENTIALS_EXISTS`, and the dangling target is not created). Control characters are refused before open (no file left behind). On a write/fsync error the file is unlinked in `finally`. A hard kill mid-write can leave a partial file, but it is created 0600 (umask can only remove bits), so it can never be 0644. No atomic temp+rename. The loader rejects a truncated file as a JSON parse error. Windows: created with mode 0o600 (write bit present, so not read-only), ACL inherited from the directory; fchmod skipped. | Optional: write to a temp name with O_EXCL, then rename. |
| F8 | LOW | scripts/v6/real-device.mjs:71-73 | `--no-clipboard` works as described (`flag()` is defined at :39). The default still copies the per-run bridge secret to the Windows clipboard (Win+V history / cloud clipboard). The code comment refers to a recording runbook that opens the bridge from the 0600 file (`Start-Process msedge --app=...`), but no file under docs/ at b2377da mentions `--no-clipboard`, `clipboard` or `Start-Process` (grep returned nothing). Also, opening the bridge via a command-line `--app=URL` puts the secret in the process command line. The non-`--demo` mode still prints the full bridge URL to the terminal (unchanged, by design). | Update the video runbook to require `--demo --no-clipboard`, and say how the link is opened without showing it on screen. Consider making no-clipboard the default in `--demo`. |
| F9 | INFO | scripts/v6/showcase.mjs:85-88, tests/v6/showcase-log-reconcile.test.mjs:16-21 | The viewer now HTML-escapes labels, kind, text and time; className is restricted to `[a-z]`. The console line was already `termSafe` at 60cfd20 (unchanged). The viewer test is a source-regex pin, not a DOM test: it catches the listed reverts but not an equivalent unsafe rewrite. | Acceptable for a MOCK showcase. |
| F10 | INFO | full suite | 3 OS-isolation tests (tests/v2/os-isolation.test.mjs ×2, tests/v3/deployment.test.mjs ×1) fail when the worktree is under <cloud-tmp> (mode 0700: the unprivileged probe uids get ENOENT / MODULE_NOT_FOUND). They fail the same way on 60cfd20 (3/6 pass). From /var/tmp/sbxrev they pass 6/6. In the full suite from /var/tmp/sbxrev, test 107 ("OS: access matrix + all 24 techniques") failed once. It passed 2/2 when that file was rerun alone. I did not root-cause this; it looks like a load-dependent flake. | Rerun on CI. Do not record it as PASS without a clean full run. |

## Questions answered

1. **Inherited action names**: no longer dispatch in V3 (chain.mjs:274), V4 (:624-626), V5 (:577) or V6 (wraps V5; checkGates does no lookup by type). The V5 fallback into `V4.applyTransition` is covered by the V4 own-check, and `UNFREEZE` is blocked before it. Other `[a.type]` lookups: `CRITICAL.has`, `V3_PASSTHROUGH.has` and `V4_FORBIDDEN.has` are Sets. `requiredLevelOf` (v5/root/command.mjs:32, `REQUIRED_LEVEL[a.type] ?? 'TRUSTED'`) can return a function for an inherited type, but it is only reachable for a HANDLERS5 own type or after dispatch, so it is not exploitable. The redteam actuators (`ACTION_SPECS[a.type]`) are test/simulation tooling, not on Root paths. The V2 wire uses hasOwnProperty. The MCP interactor (integrations/external-interactor) has no Root submit route. **Non-action-name keys: F1 (reachable, commits), F2 and F3 (fail closed).**
2. **Behaviour of fingerprint / approval / FREEZE / HOLD_RELEASE / recovery**: `git diff --stat` touches only the dispatch lines in the src/v2, v3, v4, v5 chain files, plus gmail.mjs and three scripts. No vault, console, device, biometric, emergency or recovery-service file changed. The only semantic change for legitimate input is that a non-string `a.type` (for example an array coercing to a handler name) is now refused. Before, such a value could reach a handler and skip the V4 `CRITICAL.has` check. That is stricter, and legitimate clients send strings. All other suite tests pass (see counts).
3. **Gmail**: F6, F7. No regression on native Windows. Hardening on POSIX.
4. **Tests detect reverts**: see the mutation table below.
5. **Weakening of a 60cfd20 protection**: none found.

## Mutation spot-checks (my own script, one revert at a time, tests: v3/v5 prototype-action + v2 prototype-technique)

| Mutant | Result |
|---|---|
| V3 `const H = HANDLERS[a.type]` | caught (2 fail) |
| V4 `own4 = HANDLERS4[a.type] ?? null` | caught (3 fail) |
| V4 `own3` without `Object.hasOwn(H3, …)` only | survives (equivalent, F4) |
| V4 `own3 = H3[a.type] ?? null` (both guards removed) | caught (3 fail) |
| V5 `if (HANDLERS5[a?.type])` | caught (2 fail) |
| V2 `ATTACKS[msg.technique]` | caught (1 fail) |

Author's `scripts/v6/reconcile-mutations.mjs`, rerun by me: `caught 13/13, pattern errors 0`. One caveat: the O_NONBLOCK row is `failingTests: -1` (F5). The worktree was clean afterwards (`git status --short` showed only the node_modules symlink).

## Test counts

- `node --disable-warning=ExperimentalWarning --test` in <cloud-tmp>/rev (b2377da): **tests 584, pass 581, fail 3, cancelled 0, skipped 0**. The 3 failures are the OS-isolation tests, failing for the environmental reason in F10.
- Same command in /var/tmp/sbxrev (b2377da): **tests 584, pass 583, fail 1** (test 107, flaky, passed 2/2 alone).
- `tests/v2/os-isolation.test.mjs tests/v3/deployment.test.mjs` alone in /var/tmp/sbxrev: 6/6 pass. On 60cfd20 under <cloud-tmp>: 3/6 (same environmental failure).

## Commands run (main ones)

- `git diff --stat 60cfd20 b2377da`; `git log --oneline 60cfd20..b2377da`; `git diff 60cfd20 b2377da -- src scripts tests`
- grep for bracket lookups on request fields across src/v2..v6, scripts/v6, src/v6/emergency/console.mjs, integrations/
- Probe p1.mjs (V6 world; HOLD_EXPIRE / RAPID_USE_EXPIRE with inherited IDs) on b2377da and 60cfd20; p2.mjs (verifyWorld6 after the phantom commit)
- Probe g.mjs (Gmail writer/loader: new, existing, dangling symlink, control char, 0600/0644/symlink/FIFO load, umask 0); baseline 0644/symlink load on 60cfd20
- Mutation script (six single-line reverts above); `node scripts/v6/reconcile-mutations.mjs <scratch>/recmut.json`
- Full suite (see counts)

## Not checked / NOT_RUN

- Windows native behaviour of the Gmail loader/writer and of `--no-clipboard` (no Windows host). Windows conclusions come from code reading and Node constant semantics.
- Real Gmail OAuth flow, the real-device runner, Edge/WebAuthn/Windows Hello, the bridge launch.
- MCP interactor test suite (integrations/external-interactor, TypeScript), CodeQL, GitHub CI, full Stryker-style mutation runs (<cloud-tmp>/m6 and <cloud-tmp>/mr were not touched).
- V1, V2b and Track C branches (SSTP PR #27, V1/V2 legacy hardening).
- Root cause of the test 107 flake under full-suite load.
- An exhaustive audit of every `s.*[id]` lookup in V3/V4 recovery and governance handlers. I sampled them: the recovery channel/IDV/registrar/guardian lookups fail closed on signature verification with an undefined key.
