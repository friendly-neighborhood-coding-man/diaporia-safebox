# Independent security review of SafeBox audit PR #17 and patches #18–#25

Status: review artifact only. Do not merge. Nothing in PRs #15–#25 was modified, pushed, rebased, or deployed.

Reviewer: a separate Cursor cloud agent from the author of PR #17 and PRs #18–#25. The previous agent's tests are not treated as evidence. Every executed claim below names the command, the commit, and the observed result from this run.

Node: v22.23.4. Host user is not root. Product OS-isolation tests skipped themselves with `OS isolation NOT VERIFIED`. That result is left as skip. It is not a pass.

Pinned commits:

| PR | Role | SHA |
|---|---|---|
| #15 | V6 integration base | `8cd505bef9661f43eb94fbc0eac9e8fd4396702d` |
| #16 | SSTP base | `c256ffaabf534b850dde4adf90e5f527da80fb4c` |
| #17 | Audit report | `11bd93307bc64d00554e311b51dc00c7d31339de` |
| #18 | verifySlot | `27072174317791079e999aa82c07cd2358ee91b4` |
| #19 | V2 keygen | `d33a68272a0082df02401620b7e65d4b9ba2954a` |
| #20 | Root dispatch | `8778ce06bc4182a14e7c1b27a553af54ec1920c7` |
| #21 | Launcher argv | `8fdcd9a48e40304b52e15095986b119a708f3edc` |
| #22 | Gmail credential files | `a77d9a784229660ec8d5615895ead806ba17458f` |
| #23 | V1 key files | `631fa421ed26067f5f10a5ff04e32680d3bc91c7` |
| #24 | Owner log read | `e62c3e5fb59815dfa290dd1435ecd830a5a76d52` |
| #25 | Showcase log line | `3f600c8ec061199f49603690544eacae571ce873` |

Local integration of #19–#25 onto #15, not pushed: `review/indep-v6-integration` at `f087715eb8c08b83370cd997ed5ad149c333a0f1`.

Evidence labels used below are exactly one of: Reproduced independently / Supported by static review only / Inconclusive / Not run / False positive / Residual risk.

## 1. Summary table

| PR | Finding | Original vuln exists? | Repro valid? | Claimed vs this review | Patch complete? | New risk? | Evidence | Verdict |
|---|---|---|---|---|---|---|---|---|
| #20 | Prototype names dispatch as Root handlers | Yes, and wider than the report | Yes. Real `submit` / `submitRaw`, no test hooks | High vs **High** | Code yes for the names and inherited functions tried. Their tests do not cover V3 | No new dispatch bypass found | Reproduced independently | ACCEPT_WITH_CONDITIONS |
| #18 | `verifySlot` check-then-read | Yes | Yes for the lstat/read window. Their race test does not prove the patch | Medium vs **Medium** | No. Post-open swap still returns success and leaves a symlink, including a directory | The new race test passes with `O_NOFOLLOW` removed | Reproduced independently | REQUEST_CHANGES |
| #21 | Root launcher interpolates paths into `sh -c` | Yes | Yes. The exact `find ${ROOT} ... ${NODE}` string created a marker | High (if that launcher runs) vs **High under that condition** | The `find` / `stat` / `command -v` sinks are fixed. Red-team mount string is still a shell | Helper passes a leading `-` path to `find` without `--` | Reproduced independently | ACCEPT_WITH_CONDITIONS |
| #19 | Keygen symlink follow and skipped public key | Yes | Yes. Real `keygen.mjs` process | Medium vs **Medium** | Yes for the four behaviors executed | No | Reproduced independently | ACCEPT |
| #22 | Gmail credential load/write follows symlinks and ignores mode | Yes | Yes for load and for `writeFileSync` as the setup script calls it. OAuth dance not run | Medium vs **Medium** | Yes for load and create | No | Reproduced independently | ACCEPT_WITH_CONDITIONS |
| #23 | V1 key load follows a symlink to a mode `0600` file | Yes | Yes | Medium vs **Medium** | Yes for the loads executed | No | Reproduced independently | ACCEPT |
| #24 | Owner-log view follows a symlink | Yes | Yes | Medium vs **Medium** | Read path yes. Writer still follows a symlink | No new read bypass | Reproduced independently | ACCEPT_WITH_CONDITIONS |
| #25 | Showcase `console.log` splits on a newline | Yes | Yes for the console template. Browser runner not run | Low vs **Low** | CR/LF yes. U+2028, U+2029, and ANSI CSI remain | No | Reproduced independently | ACCEPT_WITH_CONDITIONS |

## 2. Per-patch verdicts

### PR #20 — Root handler dispatch — ACCEPT_WITH_CONDITIONS

Original, `8cd505b`:

- `src/v5/root/chain.mjs:577` enters the V5 commit path when `HANDLERS5[a?.type]` is truthy, then calls `HANDLERS5[a.type](...)` at line 585. That call is a method call, so `this` is the handler table. Inherited functions therefore run instead of throwing.
- `src/v3/root/chain.mjs:273-279` copies the function out and calls it bare, then commits `seq`, `usedNonces`, and `head`.
- `src/v4/root/chain.mjs:624` uses `HANDLERS4[a.type] ?? ...` and then calls the extracted function. `toString` and `constructor` do not throw on a bare call, so they commit.
- `src/v6/root/chain.mjs:105` calls `V5.applyTransition`. V6 has the same hole.
- `src/v2/general/zone.mjs:34` and `:45` do the same lookup for attack technique names.

Independent reproducer: `/tmp/indep-review/repros/pr20-prototype.mjs` against `8cd505b` and `8778ce0`.

On `8cd505b`:

- V5 and V6 `submit` of `toString`, `constructor`, `valueOf`, `hasOwnProperty`, `isPrototypeOf`, `propertyIsEnumerable`, and `toLocaleString` returned `ok: true` with empty effects. V5 sequence moved `0 → 7` and the head changed.
- V3 and V4 committed `toString` and `constructor` (`seq` 1 then 2). The other built-ins returned `INTERNAL_ERROR` and did not commit, because a bare call sets `this` to `undefined` and those built-ins throw.
- `__proto__` did not commit (`INTERNAL_ERROR`, sequence stayed 0).
- `tostring`, `constructor.prototype`, and a non-string type did not commit.
- `HOLD_EXPIRE` with an unknown id returned `HOLD_UNKNOWN`, so a real handler is still reached.
- Placing `function (s) { s.epoch = 99 }` on `Object.prototype` and submitting that name committed. Epoch moved `1 → 99`, `ok: true`, `seq` 1. The same submit on `8778ce0` returned `TRANSITION_TYPE_UNKNOWN` and left epoch at 1.
- V2 `runAttack` invoked `toString` and `constructor` as empty successes, and ran an inherited function planted on `Object.prototype`. On `8778ce0` those names returned `unknown technique`.

The audit's reproduction (`toString` and `constructor` commit) is valid. It is narrower than the bug. Any inherited function is a handler. On V5/V6 that function receives the state object as its first argument and its mutations are committed. Built-in methods do not move mock funds. A custom function on `Object.prototype` requires prior JavaScript execution in the process, so that variant is not a remote prototype-pollution-to-RCE by itself. It is still an unauthenticated root commit. High is justified.

Patch `8778ce0` uses `typeof === 'string' && Object.hasOwn(...)` in V2, V3, V4, and V5. V6 goes through V5. On the patched tree every name above was rejected, sequence stayed 0, and `HOLD_EXPIRE` still returned `HOLD_UNKNOWN`.

Regression, both on the host, not inside a network namespace:

- `8cd505b`: `node --test tests/v2/*.test.mjs` → 47 pass, 2 skipped (OS isolation), 0 fail.
- `8cd505b`: `tests/v5/buffer.test.mjs` and `tests/v3/authority-attacks.test.mjs` → 28 pass.
- `8778ce0`: those files plus the two new prototype tests → 30 pass. V2 files plus the V5 prototype test → 48 pass, 2 OS skips.

Mutants on `8778ce0`, restored afterward:

- Restoring `if (HANDLERS5[a?.type])` makes `tests/v5/prototype-action.test.mjs` fail (0 pass, 1 fail).
- Restoring only the V4 lookup makes that same V5 test fail. V5 falls through into V4, so the V5 test does cover the V4 line.
- Restoring only `const H = HANDLERS[a.type]` in V3: `tests/v5/prototype-action.test.mjs` and `tests/v2/prototype-technique.test.mjs` still pass (2 pass, 0 fail). An independent V3 `submitRaw('toString')` then returns `ok: true`, `seq` 1. Their tests do not protect the V3 edit.

Condition: add a direct V3 regression that fails when the V3 line is reverted. The patch code itself held for every variant executed here, including `Object.prototype` pollution, case differences, and non-string types.

`Object.create(null)` is not how these tables are built. `Object.hasOwn` is the right check for a normal object, and it is not fooled by a shadowed `hasOwnProperty`.

Sibling not patched, static only: `ACTION_SPECS[a.type]` in the red-team actuators checks `typeof a.type === 'string'` and then reads `.req`. An inherited function would throw rather than commit. Not executed. Out of this patch's stated scope.

### PR #18 — `verifySlot` — REQUEST_CHANGES

Original `verifySlot` at `c256ffa`, `secure-transition/src/package/install.mjs:63-68`, `lstatSync`s a path and later `readFileSync`s that same path. `readFileSync` follows a symlink. A planted symlink is already rejected by `lstat`, so the static symlink test does not show the bug. The bug is the window between the two path operations.

Independent interposer: `/tmp/indep-review/repros/slot-swap.c` and `pr18-verifyslot.mjs`. It hooks `syscall(SYS_statx)`, which is how this Node build implements `lstat` and `fstat`. It does not replace `verifySlot`. Measurement `lstat` deletes the trigger environment variables first, so the probe's own `lstat` cannot perform the swap.

On `c256ffa`, swap on the no-follow `statx` of the slot file:

- Same bytes as the manifest: `verifySlot` returns success and the path is left as a symlink. `{"error":null,"st":{"symlink":true,"file":false}}`.
- Different bytes: `SLOT_DIGEST_MISMATCH`. The read followed the symlink. The audit's same-bytes test does not show that content confusion. It is real.

On `2707217`, the same statx-timed swap does not fire during `verifySlot`. The file stays a regular file and verification succeeds. That specific lstat-then-`readFile` window is closed, because the patch opens with `O_RDONLY|O_NOFOLLOW|O_NONBLOCK` and reads that descriptor (`install.mjs:59-89` at `2707217`).

The patch does not uphold the invariant stated in its own test comment ("a successful verify must not leave a symlink"):

- Swap on the following `fstat` (`statx` with `AT_EMPTY_PATH`), which is after `open` and before return. Same bytes: success, and the path is a symlink.
- The same fstat-timed swap of a subdirectory (`rename` the directory aside, symlink the name at another directory with the same bytes): success, and that directory entry is a symlink. `readSlotEntry` returns `{dir:true}` and closes the descriptor (`install.mjs:75` and `:99`), then `walk` uses the path. `readdirSync` follows a directory symlink.

Their race test (`tests/unit/verify-slot-race.spec.mjs`) accepts either an error or "success and the path is still a regular file". On this Node, the patched reader never `statx`s the path, so their preload never swaps during `verifySlot`, and the success branch passes. Mutant: delete `O_NOFOLLOW` from `OPEN_NOFOLLOW` and run that file. Result: the race test **passes**, the planted-symlink test **fails** (1 pass, 1 fail). The race test does not notice the removal of the flag that is supposed to close the race. The planted-symlink test does. The audit's sentence "Removing `O_NOFOLLOW` makes the planted-symlink test fail" is true. Presenting the race test as evidence the race is closed is not.

Existing suite, host, not a network namespace:

- `c256ffa`: `node --test tests/unit/*.spec.mjs` → 30 pass, 0 fail.
- `2707217`: same command → 32 pass, 0 fail.

Severity Medium is fair. The attacker is same-user. SSTP OS isolation and malicious-publisher containment were not run and are still absent. Do not upgrade those to pass.

Required change: before returning success, compare the directory entry that remains (open the parent, `fstatat` the name with `AT_SYMLINK_NOFOLLOW`) to the inode that was hashed, including directory entries that are later walked. Replace the race test with one that fails when `O_NOFOLLOW` is removed and when a post-open replacement leaves a symlink.

### PR #21 — V2 launcher command construction — ACCEPT_WITH_CONDITIONS

Original `scripts/v2/run-isolated.mjs:35` at `8cd505b`:

```text
find ${ROOT}/src ${ROOT}/scripts ${ROOT}/node_modules ... ; stat -c '%U %a' ${ROOT}/src/v2/sensitive/policy.mjs ${NODE}
```

passed to `sh -c`. `ROOT` is the resolved script directory. `NODE` is `process.execPath`. This run executed that exact string with both values containing `;touch MARKER;#`. The marker file was created (`exact_marker:YES`) even though `find` then reported `No such file or directory`. The full launcher was not executed. It requires real root, `useradd`, and `setpriv`. High is justified only when that root launcher is actually started from a path or a Node binary whose path contains shell metacharacters. That precondition is realistic for a quoted `sudo node "/path;with;metacharacters/scripts/v2/run-isolated.mjs"`. It is not a remote injection.

`command -v ${b}` at line 29 uses a hardcoded name list. It is not the demonstrated bug. `scripts/v2b/run-redteam.mjs` has the same `find` pattern and a separate `sh -c` for mounts.

Patch `8fdcd9a` runs `find` and `stat` through `execFileSync` argument vectors (`src/v2/launch/argv-exec.mjs`). `writableLines` on a directory whose name contains `;touch MARKER;#` did not create the marker. `shellSingleQuote` round-tripped a value containing quotes, a newline, and `$(touch ...)`, and the marker was not created. `commandOnPath('a;id')` is false. `commandOnPath('sh')` is true.

`tests/v2/argv-exec.test.mjs` on `8fdcd9a`: 3 pass. Mutant: `execArgv` joins into `sh -c`. The separator test and the `codeWritableReport` test fail. The quote test still passes, which is correct because it does not use `execArgv` (2 fail, 1 pass).

Conditions, from this run and from `scripts/v2b/run-redteam.mjs:70`:

- The general-zone mount command is still one shell string. `MASK` paths are interpolated without `shellSingleQuote`. Today `MASK` is a constant list of absolute paths with no metacharacters. A later edit that puts a variable path there is not caught by the `find` test.
- `writableLines(['-print'])` on `8fdcd9a` returned `['.', './package-lock.json', './CONTRIBUTING.md']`. `find` treated a leading `-` as an expression. Launcher paths come from `resolve` and `process.execPath`, so they are absolute and this does not reopen the root-launcher bug. The new helper does not pass `--` before path arguments. `stat -c '%U %a' -c` fails as an option parse, which is safe only because it throws.
- `writableLines` swallows `find` failures and returns the lines it has. An empty report is what the launcher records as "not writable". The original launcher also did not abort on that check. It only stored the text.
- `commandOnPath` still executes `sh` from `PATH`. The original did too.

Windows was not run. The launcher exits unless `process.platform === 'linux'`.

### PR #19 — V2 keygen — ACCEPT

Original `src/v2/launch/keygen.mjs:11-22` at `8cd505b`. Independent driver spawned `node src/v2/launch/keygen.mjs <base> sens 0`. Synthetic keys only.

On `8cd505b`:

- Public path as a symlink to a canary: exit 0, canary overwritten with `ed25519:...`, symlink left in place.
- Private key present and public key removed: exit 0, public key still absent, private bytes unchanged.
- Private path as a symlink to an existing non-key file: exit 0, target unchanged. `existsSync` follows the symlink and the function skips. The audit's dangling-symlink case is different and was also executed: exit 1, `EEXIST`.
- Group-readable private key (`mode` 0640) with the public key removed: exit 0, public key still absent. The permissive file is not re-checked.

On `d33a682` the same four calls: canary preserved and the public path is a regular file; the missing public key is republished from the same private key; the private symlink exits 1 with `KEY_PATH_SYMLINK` and the target is unread; the 0640 file exits 1 with `KEY_FILE_TOO_PERMISSIVE`.

`tests/v2/keygen-exclusive.test.mjs`: 5 pass. Full `tests/v2/*.test.mjs` on this commit: 52 pass, 2 OS-isolation skips, 0 fail. That matches the audit's 52, on the host rather than inside their network namespace.

Mutant: `readPrivate` opens without `O_NOFOLLOW`. The private-symlink test fails. The other four tests still pass (4 pass, 1 fail). Those four cover the public symlink, republish, mode, and concurrency, so their survival is expected.

No new bypass was found in the executed cases. `publishPublic` unlinks a symlink (does not follow it) and `rename`s a new file into place. Same-user replacement of a `0600` file by its owner remains outside this patch, as it should.

### PR #22 — Gmail credential files — ACCEPT_WITH_CONDITIONS

Original `src/v6/notify/gmail.mjs:30-33` calls `statSync` and ignores the result, then `readFileSync`. `scripts/v6/gmail-oauth-setup.mjs:61` is `writeFileSync` without `O_EXCL` or `O_NOFOLLOW`.

On `8cd505b`, synthetic token strings, no network:

- Mode `0644` load returned the sender.
- A symlink to a mode `0600` file load returned the sender.
- `writeFileSync` on a symlink, the call the setup script makes, replaced the canary with the credential JSON and left the symlink.

On `a77d9a7`: `0644` raises `GMAIL_CREDENTIALS_TOO_PERMISSIVE`; `0600` loads; a symlink load raises `GMAIL_CREDENTIALS_SYMLINK`; `writeGmailCredentialFile` on a symlink raises `GMAIL_CREDENTIALS_EXISTS`, canary unchanged; a new file is mode `0600` (384) and loads.

`tests/v6/gmail-cred-file.test.mjs` and `tests/v6/gmail.test.mjs`: 10 pass. Original `gmail.test.mjs` alone: 8 pass.

Mutants on `a77d9a7`, restored after:

- Delete the mode check: test 1 fails, test 2 passes (1 fail, 1 pass).
- `loadGmailCredentials` opens without `O_NOFOLLOW`: test 1 fails with `Missing expected exception` at the symlink assertion (line 23). Test 2 still passes because the write path keeps `O_EXCL|O_NOFOLLOW`.

Condition: the refresh-token control-character check lives only in `scripts/v6/gmail-oauth-setup.mjs` and was not executed. The OAuth browser dance and any call to Google were not run. `writeGmailCredentialFile` itself does not apply that check. A same-user process can still read a mode `0600` file. That residual is unchanged and should stay documented.

### PR #23 — V1 key files — ACCEPT

Original `src/v1/authz.mjs:55-57` and `src/v1/near/executor.mjs:19-21` use `statSync` (follows symlinks) and then `readFileSync`.

On `8cd505b`, synthetic keys, no network: a symlink to a mode `0600` owner file loaded (`publicKey` returned). A symlink to a mode `0600` executor file loaded (`account` `mock.synthetic`). Mode `0644` on the owner file was already rejected with `OWNER_KEY_FILE_TOO_PERMISSIVE`. The hole is substitution of another correctly mode-restricted file, not a mode bypass.

On `631fa42`: both symlinks raise `OWNER_KEY_FILE_SYMLINK` and `EXECUTOR_KEY_FILE_SYMLINK`. The regular `0600` files still load. `0644` is still rejected.

`tests/v1/keyfile-nofollow.test.mjs` and `tests/v1/executor-verifier.test.mjs`: 6 pass. Original executor-verifier file alone: 5 pass.

Mutant: both readers open without `O_NOFOLLOW`. `tests/v1/keyfile-nofollow.test.mjs` fails (0 pass, 1 fail).

`writeOwnerKeyFile` still uses `flag: 'wx'`. That flag does not follow a final symlink (`EEXIST`). Not the bug that was demonstrated.

### PR #24 — Owner log — ACCEPT_WITH_CONDITIONS

Original `OwnerSimulator.view` at `src/v2/supervisor/owner.mjs:31-35` uses `existsSync`, `statSync`, and `openSync(path, 'r')`, all of which follow a final symlink.

On `8cd505b`: a real log view saw 1 policy. A symlink to a file containing `{type:'POLICY', policy:{policyId:'forged'}}` produced a view whose policy id was `forged`.

On `e62c3e5`: the same symlink raises `OWNER_LOG_SYMLINK`. The real log still views. `tests/v2/owner-log-fd.test.mjs`: 1 pass.

Mutant: open without `O_NOFOLLOW`. That test fails (0 pass, 1 fail).

Condition, reproduced on the patched file: `#log` at `src/v2/supervisor/owner.mjs:25` is still `appendFileSync`. Pointing `logPath` at a symlink wrote the policy JSON into the target and left the symlink in place. `view` of that symlink now throws, so a reader of the configured path fails closed. A writer aimed at a symlink still diverts the issuance record. The scheduler race without a planted symlink was not won. The audit's statement of that limit is accurate.

### PR #25 — Showcase log line — ACCEPT_WITH_CONDITIONS

Original `scripts/v6/showcase.mjs:73` prints `` `[${clip}] ${kind.padEnd(7)} ${text}` ``. Text `prepared\n[main] OK      forged` is two physical lines. Reproduced by evaluating that template.

Patch `src/v6/showcase-log.mjs:3` replaces `\r` and `\n` with a space. The newline and CR/LF samples become one line. `tests/v6/showcase-log.test.mjs`: 1 pass. Mutant: `flat` returns the string unchanged. That test fails.

Still two segments after the patch: U+2028 and U+2029. An ANSI CSI (`\u001b[2A`) is unchanged and can move the cursor in a terminal. The structured `events` array still stores the raw text. The HTML viewer builds one element per event and escapes `&<>` in the text; `kind` is concatenated into `innerHTML` without escaping (`showcase.mjs` around the viewer script). That is a separate local-viewer issue, not what CodeQL flagged, and the browser runner was not executed. Low severity for the console newline is right.

## 3. Integration

### V6 patches #19–#25 on PR #15

`git cherry-pick` of `d33a682`, `8778ce0`, `8fdcd9a`, `a77d9a7`, `631fa42`, `e62c3e5`, and `3f600c8` onto `8cd505b` produced no conflicts. The commits touch disjoint files. Local branch `review/indep-v6-integration`, tip `f087715eb8c08b83370cd997ed5ad149c333a0f1`. Not pushed.

Smoke on that tip: `generateZoneKeys` wrote a mode `0600` private key and a matching public key; `OwnerSimulator` appended to the log `keygen` had created and `view` saw that policy; V6 `submit` of `toString` returned `TRANSITION_TYPE_UNKNOWN` with sequence still 0; `HOLD_EXPIRE` for a missing id still returned `HOLD_UNKNOWN`.

Full project script equivalent, host, not a network namespace, not root:

```text
cd /tmp/review-wt/v6-int   # f087715eb8c08b83370cd997ed5ad149c333a0f1
node --disable-warning=ExperimentalWarning --test --test-timeout=120000
```

Result: 586 tests, 583 pass, 0 fail, 3 skipped, duration about 26s. The three skips are the OS-isolation tests (`OS isolation NOT VERIFIED`). They stay skipped. Cargo contract tests were not run.

In-process tests whose names include `LOCAL_GATE` and `HIGH_ASSURANCE` ran and passed, including the test that expects a forged gate beside a UV assertion to be accepted under `LOCAL_GATE`, and the tests that expect `HIGH_ASSURANCE` to fail closed. That is the in-process software behavior. It is not a TPM or laptop probe, and it does not add an independent signer. `LOCAL_GATE` same-user signing remains a documented residual. Do not read the green names as a hardware pass.

No semantic clash showed up between keygen's no-follow create and the owner-log reader. The owner-log writer limitation from #24 is still present on the combined tree because #24 does not change `#log`.

### PR #18 on PR #16

#18 is already one commit on `c256ffa`. Applying it is that commit. No merge conflict. Unit suite at `2707217`: 32 pass, 0 fail. The post-open symlink residual in section 2 is present on that commit. SSTP `tests/os` was not run. OS isolation and malicious-publisher containment remain not implemented and were not run.

## 4. Overall verdict

**BLOCKED_FOR_INTEGRATION**

Blocking item: PR #18. The lstat-then-`readFile` window is fixed, and the new race test still passes after `O_NOFOLLOW` is removed. A swap after `open` makes `verifySlot` return success while a symlink, including a directory symlink, remains. Do not describe that patch as closing the stated invariant.

PRs #19–#25 cherry-pick onto #15 with no conflicts, and the Node suite on that tree is green apart from the three OS-isolation skips. They are not the merge blocker. They should not be described as unconditional either:

- #20 needs a V3 regression. The V3 edit is correct and currently untested by the suite that claims to lock it.
- #21 still builds a shell for red-team mounts, and the new `find` helper does not use `--`.
- #24 still appends the owner log through `appendFileSync`.
- #25 still lets U+2028, U+2029, and ANSI CSI through the showcase line.

Operator approval stays required. This branch is a review artifact.

## 5. Where PR #17 overstates confidence

1. The `verifySlot` race test is presented as the proof the race is closed, including in `VERIFICATION.md`'s post-fix 32/32 and in the finding's "Post-fix" row. On `2707217` that test passes with `O_NOFOLLOW` removed. Its success branch is also taken when the preload never runs, which is what the patched code does on a statx-only preload. The planted-symlink test is the one that actually fails closed.
2. The prototype finding is described as `toString` and `constructor` committing an empty transition. That reproduction is valid. It omits that V5/V6 commit every inherited function that can be called as a method, and that a function installed on `Object.prototype` can change committed state (epoch `1 → 99` on `8cd505b`). The patch stops that variant. The report's test does not stop a V3-only revert: their V5 and V2 tests stayed green while V3 `toString` committed.
3. `VERIFICATION.md` ties several "pass" rows to a network namespace (`unshare --user --map-root-user --net`, `ENETUNREACH`). This review did not run that wrapper. The same unit files passed on the ordinary host. The namespace result is not confirmed here. It is also not contradicted.
4. The CodeQL 17-row classification (6 exploitable, 5 invariant, 6 false positive) is taken from workflow logs after an API 403. Those logs were not re-read in this review. The counts are not independently confirmed. Two false-positive calls were checked directly: `Map.get('constructor')` is `undefined` until that key is inserted (`src/v2/launch/run-controller.mjs:39`), and the notification cleaner replaces `<` and `>` before the case-sensitive `<script>` oracle in `src/v5/sim/scenarios.mjs:215`. Those two classifications hold. The other rows were not re-derived from CodeQL output.
5. "V6 full root suite (571 tests) NOT_RUN" is an accurate description of what that audit ran. It should not be read as the current combined tree. This review's `node --test` on `f087715` is 586 tests, 583 pass, 3 OS skips, 0 fail.
6. The report is explicit that one author did audit, test, patch, and verification. That disclaimer is accurate and is not an overstatement.

## 6. What this review did not run

| Item | Why |
|---|---|
| `unshare` network namespace around the tests | Not required to observe the defects. The audit's `ENETUNREACH` claim is therefore not confirmed here. |
| Product OS isolation (`tests/v2/os-isolation.test.mjs` and the V3 OS matrix) | The suite skipped them: Linux root, `setpriv`, `unshare`, and `useradd` were not used. Left as `OS isolation NOT VERIFIED`. |
| SSTP `tests/os`, uid separation, malicious-publisher containment | Not implemented. Not run. Not upgraded. |
| `scripts/v2/run-isolated.mjs` and `scripts/v2b/run-redteam.mjs` as processes | They require real root and OS principals. The shell string was executed. The launcher was not. |
| Gmail OAuth browser flow and any Google endpoint | Forbidden. Synthetic fields and the local file API only. |
| Showcase browser runner | Not started. Only the log-line function and the console template. |
| Mainnet, Testnet, funded transactions, real wallet keys | Not used. |
| Cargo contract tests | Not part of `npm test`. Not run. |
| CodeQL API and the disposable workflow logs | Not re-fetched. |
| `LOCAL_GATE` laptop / TPM probe | No operator hardware. In-process tests with those names did run and still show the documented forged-gate acceptance. |
| A fresh hardware `HIGH_ASSURANCE` signer | Not present. In-process fail-closed tests did run. |
| Windows | Host is Linux. |
| Full mutation campaigns (`npm run mutations`, V5/V6 mutation scripts) | Not run. Only the single-line mutants named above. |
| Owner-log scheduler race without a planted symlink | Not won. |
| Push or merge of the integration branch | Not done. |

## Commands (this run)

Prototype, both trees:

```text
node --disable-warning=ExperimentalWarning /tmp/indep-review/repros/pr20-prototype.mjs /tmp/review-wt/v6-orig
node --disable-warning=ExperimentalWarning /tmp/indep-review/repros/pr20-prototype.mjs /tmp/review-wt/v6-pr20
```

`verifySlot`:

```text
node --disable-warning=ExperimentalWarning /tmp/indep-review/repros/pr18-verifyslot.mjs \
  /tmp/review-wt/sstp-orig/secure-transition statx
node --disable-warning=ExperimentalWarning /tmp/indep-review/repros/pr18-verifyslot.mjs \
  /tmp/review-wt/sstp-pr18/secure-transition statx
node --disable-warning=ExperimentalWarning /tmp/indep-review/repros/pr18-verifyslot.mjs \
  /tmp/review-wt/sstp-pr18/secure-transition fstat
```

SSTP units: `node --test tests/unit/*.spec.mjs` in `secure-transition` at `c256ffa` (30 pass) and `2707217` (32 pass).

Other reproducers: `node /tmp/indep-review/repros/pr-rest.mjs <tree> <keygen|shell|gmail|owner|showcase>`, plus `v1-only.mjs` run with cwd set to the tree so `near-api-js` resolves. Exact launcher string result: marker created.

Integration suite command and result are in section 3.
