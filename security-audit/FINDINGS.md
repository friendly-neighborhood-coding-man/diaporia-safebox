# SafeBox defensive security audit

Status: **READY_FOR_OPERATOR_SECURITY_REVIEW**. Nothing in this audit was merged or deployed. No previously unverified security feature was enabled.

Frozen references, left unchanged:

- V6 Hardening, PR #15, `8cd505bef9661f43eb94fbc0eac9e8fd4396702d` (`claude/v6-security-hardening`)
- SSTP V0, PR #16, `c256ffaabf534b850dde4adf90e5f527da80fb4c` (`experiment/secure-transition-v0`)

## Roles

One cloud agent performed auditor, boundary tester, patcher, and verifier. Subagents were not given a separate identity, a separate credential, or a veto. **This was not an independent review.** The verifier re-ran tests and a few single-site mutants, then wrote this report. Treat agreement between the sections as one author's consistency check.

## CodeQL source

The GitHub code-scanning API returned `403 Resource not accessible by integration`. Alerts were taken from the disposable workflow logs, not from the API:

- V6 tree: run `43615725041`, job `132510234655`, 16 results, head `be9ed8e5f127b3dcb09dd5549aea5f77be4d0034` (frozen `8cd505b` plus the audit workflow only)
- SSTP tree: run `43615726867`, job `132510240752`, 17 results, head `fffaacf4948bd1652151d4eef69e6578c7fe75e2` (frozen `c256ffa` plus the same workflow)

The queries were `security-extended` for JavaScript/TypeScript. A warning is not by itself an exploitable vulnerability. The SSTP scan is the V6 set plus `secure-transition/src/package/install.mjs:68`.

## Isolation of the test runtime

`unshare -n` failed with `EPERM` (no `CAP_SYS_ADMIN` in the parent). `unshare --user --map-root-user --net` succeeded. Inside that namespace, before any test:

- TCP `1.1.1.1:443` and `8.8.8.8:53` failed with `ENETUNREACH` (101)
- With loopback left down, TCP `127.0.0.1:9` also failed with `ENETUNREACH`
- After bringing up only `lo` with `SIOCSIFFLAGS`, TCP `127.0.0.1:9` failed with `ECONNREFUSED` (111) and `1.1.1.1:443` still failed with `ENETUNREACH`

That is an OS network namespace, not an application flag. Git pushes were not run inside it. Application config was not treated as isolation.

A user namespace maps the process to uid 0 inside the namespace. The product's OS-isolation tests treat uid 0 as "root is available" and then fail because this environment cannot actually create the deployment users. On the real uid (1000) those tests **skip**. OS isolation of SafeBox is **NOT_RUN**. See `RESIDUAL-AND-NOT-RUN.md`.

## Extra finding (not a CodeQL alert)

### F-EXTRA-1. Prototype methods are accepted as Root actions

| | |
|---|---|
| Location | `src/v5/root/chain.mjs` (pre-fix the `if (HANDLERS5[a?.type])` branch), same pattern in `src/v4/root/chain.mjs` and `src/v3/root/chain.mjs`. Commit `8cd505b`. |
| Attacker | Any caller of the in-process Root `submit` / `applyTransition` API. No owner approval. Mock state only. |
| Invariant | A transition commits only for a declared action type, and only with the evidence that type requires. |
| Reproduction | `buildV5()` then `submit({ action: action('toString', {}) })` and the same for `constructor`. |
| Pre-fix | Both returned `ok: true`. Sequence moved `0 → 1 → 2`. Head changed. Effects were empty. |
| Patch | `cursor/root-handler-own-property-15f6` (`8778ce0`). `Object.hasOwn` on the handler tables. V2 attack technique lookup got the same check. |
| Post-fix | `tests/v5/prototype-action.test.mjs` and `tests/v2/prototype-technique.test.mjs` pass inside the network namespace. |
| Mutation | Restoring `if (HANDLERS5[a?.type])` makes the V5 test fail. |
| Limit | This stops prototype-name dispatch. It does not add an approval requirement to types that are intentionally unauthenticated housekeeping. It does not move funds by itself; it does advance the chain head and consume a nonce. |

Classification: **CONFIRMED_EXPLOITABLE**. Severity: High. Confidence: High.

The CodeQL controller warnings are a different site and are false positives. This patch does not claim to fix those warnings.

## Priority 1. SSTP `verifySlot` check/read race

| | |
|---|---|
| Location | `secure-transition/src/package/install.mjs`, `verifySlot`, pre-fix lines 63–68. Commit `c256ffa`. |
| Attacker | A process that can replace a directory entry in the slot between `lstat` and `readFile`. SSTP does not provide a uid boundary, so this is a same-user assumption. |
| Invariant | A successful verify means the hashed bytes and the recorded mode came from the directory entry that remains. |
| Reproduction | `tests/unit/toctou-preload.c` swaps the path for a symlink to the same bytes on the first `statx(AT_SYMLINK_NOFOLLOW)`. |
| Pre-fix | `verifySlot` returned success and `lstat` then showed a symlink. Result: `{"error":null,"symlink":true,"file":false}`. Test exit 1. |
| Patch | `cursor/sstp-verifyslot-race-15f6` (`2707217`). One `O_RDONLY\|O_NOFOLLOW\|O_NONBLOCK` descriptor is `fstat`ed and read. |
| Post-fix | SSTP `tests/unit/*.spec.mjs`: **32/32 pass** inside the network namespace, including the two new tests and the existing property tests. External connect during that run: `ENETUNREACH`. |
| Mutation | Removing `O_NOFOLLOW` makes the planted-symlink test fail. The race test fails on the pre-fix `lstat` + `readFileSync` shape. |
| Limit | After `verifySlot` returns, a same-user writer can still replace the path. This patch does not add OS isolation or containment of a malicious publisher. |

Classification: **CONFIRMED_EXPLOITABLE**. Severity: Medium (the function contract breaks; a later same-user replace is still possible). Confidence: High.

## Priority 2. V2 keygen check-then-create

| | |
|---|---|
| Location | `src/v2/launch/keygen.mjs` lines 13 and 19 at `8cd505b`. CodeQL flags the private-key `existsSync` then `writeFileSync(..., { flag: 'wx' })`. |
| Attacker | Same user, or anyone who can plant a symlink in the public-key directory before keygen runs. Synthetic keys only. |
| Invariant | Creating keys is exclusive. A re-run publishes the public key of the private key that is actually stored. Public files are not written through symlinks. |
| Reproduction | Frozen `keygen.mjs`, disposable directory. |
| Pre-fix | Public path as a symlink to a canary: exit 0, canary overwritten with `ed25519:...`, symlink left in place. Private key already present and public key absent: exit 0, public key still absent. Dangling private-key symlink: `EEXIST`, exit 1 (`wx` did not follow it). |
| Patch | `cursor/v2-keygen-exclusive-15f6` (`d33a682`). Complete temp file, `link` into place, re-read on `EEXIST`, public files replaced by `rename` after `unlink` of a symlink. |
| Post-fix | `tests/v2/keygen-exclusive.test.mjs` 5/5. The in-process V2 suite inside the network namespace: 52 pass. The two OS-isolation tests were attempted only because the user namespace looks like uid 0; they are skipped on uid 1000. See residuals. |
| Mutation | Opening the private key without `O_NOFOLLOW` fails the private-symlink test. |
| Limit | `wx` already stopped a second creator from truncating the private key. The patch does not put keygen in a different uid from the rest of the process. |

CodeQL lines 13 and 19: **CONFIRMED_INVARIANT_VIOLATION** (the flagged private-key write is exclusive; the demonstrated failures are the skipped public key and the sibling public-path symlink follow, which the same patch closes). Severity: Medium. Confidence: High. The public-path overwrite itself was executed and is the exploitable behavior in that function.

## Priority 3. V2 and V2-B controller dynamic dispatch

| | |
|---|---|
| Location | `src/v2/launch/run-controller.mjs:39` and `src/v2b/launch/run-controller-rt.mjs:33` at `8cd505b`. |
| What the line is | `waiting.get(m.id)` then `w?.(m.result)`. `waiting` is a `Map` filled only with locally allocated promise resolvers. The peer chooses which in-flight id to complete and what result object to pass. It does not choose a method name. `Map.get('constructor')` does not return `Object.prototype.constructor`. |
| Assumption | CodeQL modeled the map lookup plus call as a dynamic method name. The message text matches that query. |
| Patch | None for these two lines. Changing them was not justified. |

Classification: **FALSE_POSITIVE**. The separate handler-table bug is F-EXTRA-1.

The general zone is still an untrusted RPC peer. Repair results taken from it are only as trustworthy as that design. V2-B's `trustedReplay` flag is the project's own mitigation and was not changed here.

## Priority 4. V2 shell construction

| | |
|---|---|
| Location | `scripts/v2/run-isolated.mjs` (CodeQL sink reported at the `sh` helper, line 31). The interpolated command is the `find ${ROOT} ... ${NODE}` string. `scripts/v2b/run-redteam.mjs:38` is the related indirect-command alert. Commit `8cd505b`. |
| Attacker | Someone who can choose the checkout path or `process.execPath` before an operator runs the root launcher. |
| Invariant | Launcher paths are arguments, not shell source. |
| Reproduction | The same `` find ${ROOT}/src `` template with `ROOT` containing `;touch MARKER;#`. |
| Pre-fix | `markerCreated: true`. |
| Patch | `cursor/v2-shell-argv-15f6` (`8fdcd9a`). `find`, `stat`, and `command -v` use argument vectors. The red-team mount script still uses a shell, with `shellSingleQuote`. |
| Post-fix | `tests/v2/argv-exec.test.mjs` 3/3 inside the network namespace. |
| Mutation | Joining arguments into `sh -c` makes the separator test fail (and created a stray marker, which was deleted and is not in git). |
| Limit | `run-redteam.mjs` still builds a shell for `mount && exec` inside `unshare`. The quoter is tested. `--name` was already reduced to `[A-Za-z0-9_-]` before it entered `runId`, so that particular argument was not shown to inject. The V2-A launcher path was. |

`run-isolated.mjs`: **CONFIRMED_EXPLOITABLE** if that root launcher is executed with a metacharacter in the repo path or the Node path. Severity: High under that condition, because the script is the root launcher. Confidence: High for the pattern; the full launcher was not executed (it requires real root and `useradd`).

`run-redteam.mjs:38`: **CONFIRMED_INVARIANT_VIOLATION**. Severity: Low. Confidence: Medium. The shell string was real; a working injection through the sanitized `runId` was not demonstrated.

## Priority 5. V6 Gmail credential files

| | |
|---|---|
| Location | `src/v6/notify/gmail.mjs:31` (`statSync` then `readFileSync`, mode ignored) and `scripts/v6/gmail-oauth-setup.mjs:61` (`existsSync` then `writeFileSync`). Commit `8cd505b`. |
| Attacker | A local process that can plant a symlink at the configured path, or that can read a credential file created mode `0644`. Synthetic token strings only. No Google endpoint was contacted. |
| Invariant | Credential files are regular files, mode `0600`, and are not followed as symlinks. |
| Pre-fix, loader | Frozen `loadGmailCredentials` returned the sender for a mode `0644` file and for a symlink to that file. |
| Pre-fix, setup script | The OAuth browser dance was **NOT_RUN**. The old write is `writeFileSync` without `O_NOFOLLOW` or `O_EXCL`. |
| Patch | `cursor/v6-gmail-cred-file-15f6` (`a77d9a7`). Load and create use one descriptor, `O_NOFOLLOW`, and mode `0600`. The setup script calls that creator. Control characters in the refresh token are refused before the write. |
| Post-fix | `tests/v6/gmail-cred-file.test.mjs` 2/2 inside the network namespace. Existing `tests/v6/gmail.test.mjs` 8/8 on the host, with a fake `fetch`. |
| Limit | A same-user process can still read a `0600` file. The token body is still stored on purpose after the state and scope checks. |

`gmail.mjs:31`: **CONFIRMED_EXPLOITABLE** for a planted symlink or a permissive file. Severity: Medium. Confidence: High.

`gmail-oauth-setup.mjs:61` file-system race: **CONFIRMED_INVARIANT_VIOLATION**. Severity: Medium. Confidence: Medium (the write API is the unsafe one; the script's OAuth path was not executed).

`gmail-oauth-setup.mjs:61` `js/http-to-file-access`: **FALSE_POSITIVE** for path control. The path is `--out`, not the HTTP request. The bytes written are the token the operator just authorized. Residual: a same-user process that can read the printed state can hit the loopback listener. That listener was not exercised.

## Priority 6. Other CodeQL alerts

### `src/v1/authz.mjs:57` and `src/v1/near/executor.mjs:21`

`statSync` (follows symlinks) then `readFileSync`. Pre-fix, a symlink to a mode `0600` synthetic key was accepted: owner signer returned `ed25519:...`, executor signer returned `mock.synthetic`.

Patch: `cursor/v1-keyfile-nofollow-15f6` (`631fa42`). Post-fix test passes inside the network namespace. Existing executor-verifier tests passed on the host.

Classification: **CONFIRMED_EXPLOITABLE** under "the configured path can be replaced with a symlink". Severity: Medium. Confidence: High. A different uid cannot plant that symlink if the parent directory is not writable by them. This audit did not re-check the deployment directory modes at runtime.

### `src/v2/supervisor/owner.mjs:34`

Pre-fix, `OwnerSimulator.view` on a symlink returned a policy map containing `forged`.

Patch: `cursor/v2-owner-log-fd-15f6` (`e62c3e5`). Post-fix test passes inside the network namespace.

Classification: **CONFIRMED_EXPLOITABLE** for a planted symlink. Severity: Medium. Confidence: High. The scheduler race between `stat` and `read` was not won without the preload technique used for `verifySlot`; the symlink is the deterministic form of the same path confusion.

### `scripts/v6/showcase.mjs` log injection (line 73 on the V6 scan, line 72 on the SSTP scan)

`console.log` of event text. A newline in `text` starts a second visual record. The showcase runner itself was **NOT_RUN** (it starts a browser).

Patch: `cursor/v6-showcase-log-line-15f6` (`3f600c8`). `showcaseLogLine` flattens CR/LF. Unit test passes.

Classification: **CONFIRMED_INVARIANT_VIOLATION**. Severity: Low. Confidence: Medium.

### `js/bad-tag-filter` at `src/v5/sim/scenarios.mjs:215` and `tests/v5/notify.test.mjs:40`

Both are case-sensitive `<script>` checks in a simulation oracle and a unit assertion. Production `src/v5/notify/notify.mjs` `clean()` replaces `<`, `>`, and `` ` `` for every case before that oracle runs. Uppercase tags do not survive as tags.

Classification: **FALSE_POSITIVE**. No patch.

### `tests/v6/fixtures/fake-winbio-helper.mjs:7`

Test double. `existsSync` then read/write of a software key file used only by tests. Not a production trust boundary.

Classification: **FALSE_POSITIVE**. No patch.

## Known limits that this audit does not change

- SSTP does not implement OS isolation or containment of a malicious publisher. In-process results are not evidence of either. **KNOWN_RESIDUAL_RISK**.
- V6 `LOCAL_GATE` same-user signing is the project's documented residual. This audit did not re-run the laptop probe. Fresh execution: **NOT_RUN**. Classification of the documented issue: **KNOWN_RESIDUAL_RISK**.
- `HIGH_ASSURANCE` is designed to fail closed when no independent signer exists. This audit did not re-run that suite. Fresh execution: **NOT_RUN**. No patch here claims to change it.
