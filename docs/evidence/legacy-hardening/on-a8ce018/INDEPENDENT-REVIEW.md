# Mission 2: independent review of the legacy V1/V2 hardening (PR #30 = #19, #21, #23, #24 + PR #28 follow-ups)

Reviewer: independent security reviewer (Claude). I checked the code and ran my own experiments. I did not rely on commit messages, comments or earlier reports.
Date: 2026-11-14. Platform: Linux 6.18, Node v22.23.4, running as root (uid 0).

- Branch reviewed: `security-research/v1v2-legacy-on-a8ce018` at **`c86d4f4e3bddf8ad7babe9aae5f416a70d7fe297`** (`<scratch>`)
- Baseline: **`a8ce01840d79166403aec159c8c05e70bd916721`**. It is an ancestor of HEAD (checked with `git merge-base --is-ancestor`). The 7 commits between them are `79f27b5 d254f5d 76c78b2 3ea8d12 a0a8afd 448e3cb c86d4f4`.
- I did not edit, commit or push any tracked file in `<scratch>`. I made two disposable worktrees: `<scratch>` (a8ce018) and `<scratch>` (HEAD). I used them for the baseline comparison and the mutation runs, then removed both with `git worktree remove --force`.
  - An untracked `docs/evidence/legacy-hardening/on-a8ce018/` already existed in `<scratch>` (mtime 21:07). It was there before my runs. I did not create it and did not touch it.
- My experiment scripts, mutation harness and TAP logs are in `<scratch>`.

## Verdict: **PASS_WITH_ISSUES**

Each patch closes the main issue it targets:

- symlink following at the final path component
- the keygen check-then-create race
- shell interpolation of launcher paths
- the size-check-then-read TOCTOU on the owner log

I confirmed each one against the baseline. The full suite is green (599/599) and no baseline test was lost.

There are still issues:

- One availability regression: a FIFO at a key or log path now hangs the process.
- Some protections are partial. The incremental owner-log view does not track file identity. Only the final path component is protected. Several defensive checks are not tested.
- Small behaviour differences that need to be documented, listed in section 2.

None of this touches V6 runtime behaviour (section 3).

## 1. Does each patch close its target issue? (all VERIFIED by experiment unless marked)

Baseline (B) is a8ce018, patched (P) is c86d4f4. Scripts: `review-m2-artifacts/exp/{kg.sh,race.mjs,fifo2.mjs,view.mjs,v1.mjs,argv.mjs}` and `review-m2-artifacts/det/{det.mjs,mode.mjs}`.

### PR #19 keygen (`src/v2/launch/keygen.mjs`): CLOSED for symlinks and the create race

| Attempt | Baseline a8ce018 | Patched c86d4f4 |
|---|---|---|
| symlink `sens/executor.key` -> canary | exit 0, key silently skipped, no pub published | `KEY_PATH_SYMLINK`, canary intact |
| dangling symlink at `sens/executor.key` | raw `EEXIST` crash | `KEY_PATH_SYMLINK`; target not created |
| symlink `pub/sens/executor.pub` -> canary | **canary overwritten** with pubkey | canary intact; symlink replaced by a regular file |
| symlink `sup/owner-log.jsonl` / `owner.keys` -> canary | followed (log opened through link) / key skipped | `KEY_PATH_SYMLINK` |
| symlink `pub/sup/clock` -> canary | **canary overwritten** ("0") | canary intact |
| directory at key path | exit 0 (skipped) | `KEY_PATH_NOT_A_FILE` |
| pre-created 0644 key | accepted silently | `KEY_FILE_TOO_PERMISSIVE` |
| pre-created garbage 0600 key | accepted silently | JSON `SyntaxError`, exit 1 |
| 24 concurrent keygens (sens+sup) x 10 rounds | **3 child failures (EEXIST)** | 0 failures, pub matches priv in every round, no tmp leftovers |
| deterministic interleave: competitor creates key between `readPrivate()==null` and `link` (`det/det.mjs`) | n/a | loser returns the WINNER key, winner's private key kept |
| same interleave with `linkSync`->`renameSync` mutant | n/a | loser **overwrites** winner's private key (so the hard link is what gives exclusivity) |

Residuals for #19:

- **F1 (Medium, availability regression, VERIFIED).** If a FIFO is at `sens/executor.key`, the patched keygen **hangs forever**. `openSync(O_RDONLY|O_NOFOLLOW)` on a FIFO blocks before the `fstat().isFile()` check can run. The baseline returned exit 0. A FIFO at `sup/owner-log.jsonl`, `labels`, or `freeze` hangs both B and P (`ensureAppendFile` opens with O_WRONLY).
  - Fix: add `O_NONBLOCK` to the read opens and the append opens, then keep the `isFile()` check. I verified that `O_RDONLY|O_NONBLOCK` on a FIFO returns at once, so `isFile()` then rejects it, and that `O_WRONLY|O_NONBLOCK` with no reader returns `ENXIO`.
  - Precondition: the attacker needs write access to the 0700 principal directory. In the OS deployment only the owner principal and root have that, so practical severity is Low–Medium.
- **F2 (Low, VERIFIED by reading, consistent with tests).** `readPrivate` does not check that `st.uid === geteuid()`, and accepts hard links (`nlink > 1`). A regular 0600 file planted by someone who can write the directory is adopted as the zone key. The baseline behaved the same way. The 0700 directory is the real control here.
- **F3 (Info).** `publishPublic` does `unlink(path)` and then `rename(tmp, path)`. The `rename` already replaces a symlink atomically without following it, so the `unlink` adds nothing. It also opens a short window where `executor.pub` / `owner.pub.json` / `clock` do not exist (ENOENT for a concurrent reader). In current launchers keygen runs before any reader starts, so there is no practical effect. If `writeNew` fails after the open, the `.pub-*` temp file is not cleaned up.

### PR #21 + follow-up (`src/v2/launch/argv-exec.mjs`, `scripts/v2/run-isolated.mjs`, `scripts/v2b/run-redteam.mjs`): CLOSED for shell injection through paths

I created a ROOT directory containing a world-writable file for each of these names: `sp ace`, `q'uote`, `dq"uote`, `nl\nline`, `$(touch MARK)`, `` `touch MARK` ``, `a;touch MARK;#`, `-delete`, `--`, `*`. I ran the exact baseline command template from `run-isolated.mjs@a8ce018` and the new `codeWritableReport` against each one.

- **Baseline:** command substitution and `;` **executed** (`MARK-dollar`, `MARK-bt`, `MARK-semi` were created). For 7 of the 10 names the writable file was **not reported**: the check silently came back clean.
- **Patched:** nothing executed. The writable file was reported for all 10 names.
- Relative operands (`rel`), dash-led operands (`-delete`), the empty string, and `stat -c` all fail with `PATH_NOT_ABSOLUTE`. NUL fails with `BAD_ARGV`. `/-x` is accepted, which is correct.
- `commandOnPath`: `a;id`, `$(id)` and `../x` give false; `sh` and `setpriv` give true.
- Mount quoting in `run-redteam` produces `... none '/home' && ...` (I checked the generated string). The only remaining shell is the `unshare ... sh -c` chain. Every element of it goes through `shellSingleQuote`, and a mutant with quoting removed is killed by the tests.

Residuals for #21:

- **F4 (Low, VERIFIED).** The `find -print` output is split on newlines. A world-writable file named `x\nFIND_FAILED spoof (0)\nnothing-here` produces three report lines, including a forged `FIND_FAILED` line. This is a report-integrity issue only. The file is still flagged, so the report is never empty. Fix: use `-print0` and split on `\0`.
- **F5 (Low, pre-existing, VERIFIED).** If a root operand such as `ROOT/node_modules` is a symlink, `find -P` never descends into it, and the report is empty even when the target contains world-writable files. B and P behave identically.
- **F6 (Info, pre-existing).** `codeWritableByOthers` is recorded in `run.json` and never asserted, in both scripts, so a writable code tree does not stop the run. The new `FIND_FAILED` line improves the report but does not enforce anything.
- **F7 (Info, VERIFIED).** If `find` output exceeds the `execFileSync` default `maxBuffer` (1 MiB), the result is `FIND_FAILED <root> (ENOBUFS)` followed by the partial lines. This fails closed (the report is not empty). The baseline used `| head -5` and never hit the limit.
- **NOT_RUN:** `scripts/v2b/run-redteam.mjs` was not run end to end (it needs the red-team brain/campaign setup). I only checked syntax (`node --check`), the export names, and the generated mount string. `run-isolated.mjs` **was** run end to end as root, through `tests/v2/os-isolation.test.mjs` (2 OS tests passed, and its keygen ran under `setpriv` as `sbx2-sens`/`sbx2-sup`). On this repo, its `codeCheck` output is byte-identical between B and P (`root 644\nroot 755`).

### PR #23 V1 key files (`src/v1/authz.mjs` `loadOwnerSigner`, `src/v1/near/executor.mjs` `loadExecutorSigner`): CLOSED for final-component symlinks and stat-then-read

| Attempt | Baseline | Patched |
|---|---|---|
| symlink -> valid 0600 key (owner / executor) | **LOADED** | `OWNER_KEY_FILE_SYMLINK` / `EXECUTOR_KEY_FILE_SYMLINK` |
| 0644 key | `OWNER_KEY_FILE_TOO_PERMISSIVE` | same |
| directory (0700) | raw `EISDIR` | `OWNER_KEY_FILE_NOT_A_FILE` |
| >1 MiB file | JSON error | `OWNER_KEY_FILE_TOO_LARGE` |
| missing | `ENOENT` | `ENOENT` (same code; syscall `open` instead of `stat`) |
| key reached through a symlinked **parent directory** | LOADED | **LOADED** (only the last component is protected) |
| hard link to key | LOADED | LOADED |
| 0600 file owned by another uid | LOADED | LOADED (no owner check) |
| FIFO (0600) at path | hangs | hangs (F1 applies too; not a regression here) |

Mode, type and content now all come from one descriptor, so the old `statSync` then `readFileSync` TOCTOU is gone. Residuals: **F8 (Low).** Intermediate-directory symlinks are still followed, and there is no owner or `nlink` check. Fixing that would need descriptor-relative traversal (openat/O_NOFOLLOW per component), which this patch does not claim to do.

### PR #24 + follow-up (`src/v2/supervisor/owner.mjs`): CLOSED for symlink-at-path and size/read TOCTOU; PARTIAL for the incremental view

| Attempt (`exp/view.mjs`) | Baseline | Patched |
|---|---|---|
| torn line, then completed | A, then A,B (offset correct) | identical (correct) |
| symlink swapped in between refreshes | **followed: accepts `VIA_SYMLINK` record** | `OWNER_LOG_SYMLINK` |
| truncated below offset | raw `ERR_OUT_OF_RANGE` | `OWNER_LOG_TRUNCATED` |
| directory at path | `EISDIR` | `OWNER_LOG_NOT_A_FILE` |
| writer: symlink at logPath | writes through link | `OWNER_LOG_SYMLINK`, target untouched (covered by the test suite) |
| **log replaced by a different inode (rename over), size >= offset** | accepts the forged tail, never sees the new head | **same: `A1,FORGED` accepted, `X0` skipped** |
| **truncate + regrow past offset (same inode)** | accepts `REGROWN` | **same** |
| log deleted after first read | stale view, no error | same |
| malformed complete line followed by a valid line | throws once; the following valid record is **permanently skipped** (offset advanced before parse) | same |
| intermediate dir symlink / hard link at path | followed / accepted | same |
| FIFO at path (view) | returns (size 0) | **hangs** (F1) |
| FIFO at path (writer) | hangs | hangs |

- **F9 (Medium as a claim gap, Low in deployment).** The incremental view keeps `offset` but not `(st_dev, st_ino)`. A regular-file replacement or a truncate-and-regrow between refreshes is not detected. The view then mixes records from two different files and accepts records it never saw from the start. The patch closes the symlink variant only.
  - Fix: record `dev/ino` on the first open and refuse (`OWNER_LOG_REPLACED`) if they change. Optionally keep a running hash of the consumed prefix and re-verify it.
  - Only the `sbx2-sup` principal (or root) can write `sup/` (0700), so the practical attacker is the log's own writer.
- **F10 (Low, pre-existing).** `v.offset` is advanced before the lines are parsed. A JSON error on one line therefore skips every following record in that chunk for good. The fix is to advance the offset per successfully parsed line, or to fail permanently.
- **F11 (Low, pre-existing).** The byte offset is recomputed as `Buffer.byteLength(decodedText)`. If the log contains invalid UTF-8, decoding inserts U+FFFD (3 bytes) and the offset drifts. Computing the cut on the Buffer (`buf.lastIndexOf(0x0a)`) avoids this.
- Writer: it uses O_APPEND, one open per record, and a `writeSync` loop. Records are small, so in practice each append is one write. Mode on create is 0600, the same as baseline `appendFileSync(..., {mode: 0o600})`. The writer does not check the mode of an existing file (neither did B).

## 2. Behavioural differences versus a8ce018 for legitimate use

1. **keygen reuses an existing key and republishes the public file** (`keygen.mjs` `generateZoneKeys`, lines ~95–135). It does *not* refuse an existing private key. When `sens/executor.key` or `sup/owner.keys` already exists, the baseline skipped both creation and the public file. The patched version reads the existing key and rewrites `executor.pub` / `owner.pub.json` from it.
2. **keygen now validates an existing key.** A non-0600 key gives `KEY_FILE_TOO_PERMISSIVE`, a non-regular file gives `KEY_PATH_NOT_A_FILE`, malformed JSON gives `SyntaxError`, a symlink gives `KEY_PATH_SYMLINK`. Previously all of these exited 0 and silently skipped. A FIFO now hangs (F1).
3. **keygen exit codes and stderr changed** (`keygen.mjs` bottom, `invokedDirectly`).
   - A usage error now gives exit **1** with `KEYGEN_USAGE`. The baseline gave exit **2** with `usage`.
   - Every error now prints only `e.code` (for example `ENOENT`, `KEY_PATH_SYMLINK`) instead of a Node stack trace.
   - The launchers only check `status !== 0`, so they are not affected.
4. **keygen sup: symlinks at `owner-log.jsonl`, `labels.jsonl` and `freeze.jsonl` are refused** (`ensureAppendFile`). Symlinks at `clock` and the pub files are replaced instead of written through (`publishPublic`). The public files are now replaced by a new inode on every run, where the baseline wrote in place.
5. **keygen mode checks are not guarded for win32** (`writeNew` and `readPrivate`). This is unlike V1, which skips them on win32.
   - On Windows, `fstat` reports group/other bits (assumed: 0o666). Patched keygen would then always fail with `KEY_FILE_TOO_PERMISSIVE`, where the baseline worked.
   - `O_NOFOLLOW` is undefined on win32, so `x | undefined` gives `x`. Symlink refusal silently does nothing there, and nothing crashes. This is assumed from Node's documented constants.
   - keygen is only called by Linux-only, root-only launchers, so there is no production impact. Of the new tests, only the writer test in `owner-log-fd` has `skip: win32`. `keygen-exclusive`, `keyfile-nofollow` and the first `owner-log-fd` test would fail on Windows. **NOT_RUN on Windows/macOS.**
6. **V1 key loaders refuse a symlinked key file** (`authz.mjs` `readRestrictedFile` ~L53, `executor.mjs` ~L18). This matters for a legitimate setup that symlinks `executorKeyFile` (used by `src/v1/runtime.mjs` L24) to a near-cli credential file. That setup worked before and now fails with `EXECUTOR_KEY_FILE_SYMLINK`.
   - New error codes: `*_SYMLINK`, `*_NOT_A_FILE` (was `EISDIR`), `*_TOO_LARGE` (new 1 MiB cap), `*_SHORT_READ`.
   - Unchanged: `*_TOO_PERMISSIVE`, `ENOENT`.
7. **Owner log view** (`owner.mjs` `view().refresh`).
   - It throws `OWNER_LOG_SYMLINK`, `OWNER_LOG_NOT_A_FILE` and `OWNER_LOG_TRUNCATED` where the baseline followed the symlink or threw `EISDIR`/`ERR_OUT_OF_RANGE`.
   - A FIFO now hangs where the baseline returned an empty view.
   - The watchdog calls `view.refresh()` inside a Proxy getter (`serve-watchdog.mjs` L18), so these errors propagate into watchdog checks and fail closed.
8. **Owner log writer** (`owner.mjs` `#log`). It throws `OWNER_LOG_SYMLINK` / `OWNER_LOG_NOT_A_FILE`. Create mode is still 0600, unchanged from the baseline.
9. **Launcher reports** (`argv-exec.mjs` `writableLines`).
   - A `FIND_FAILED <root> (<code|status>)` line now appears when `find` exits non-zero (missing root, unreadable entries, ENOBUFS). The baseline masked find's status behind `| head -5`.
   - That line is placed *before* that root's partial output.
   - Otherwise the output is identical (I verified byte equality on this repo). The 5-line limit across all roots is unchanged. `run-redteam` used `.trim()` before and uses `join('\n')` now, which gives the same result.
10. **`commandOnPath`** returns false for names outside `[A-Za-z0-9._+-]`. All callers pass constant names, so this has no effect.

## 3. Reachability from the V6 runtime (VERIFIED)

I built a transitive import graph from `src/v5`, `src/v6`, `scripts/v6` (and also `tests/v5`, `tests/v6`), following static imports, dynamic imports and `src/...mjs` string references. Script: `review-m2-artifacts/graph.mjs`.

- **Reachable: `src/v1/authz.mjs`**, through `src/v2/common/crypto.mjs` <- `src/v5/world.mjs` (and `tests/v5/verifier-independence.test.mjs`). Within that file the commits change only:
  - the `node:fs` import line (drops `readFileSync`/`statSync`, adds `closeSync, fstatSync, openSync, readSync, constants`)
  - the new private `readRestrictedFile`
  - the body of `loadOwnerSigner`

  V5/V6 import only `ownerKeyId` / `rawFromKeyId` (through crypto.mjs and `src/v2/sensitive/statements.mjs`). `grep` finds no `loadOwnerSigner`, `loadExecutorSigner` or `OwnerSimulator` in src/v5, src/v6, scripts/v5, scripts/v6, tests/v5 or tests/v6. The module still exports the same 19 names. So the V6 code paths are byte-identical, and the only effect on V6 is the changed fs import set when the module loads.
- **Not reachable:** `src/v1/near/executor.mjs`, `src/v2/launch/{argv-exec,keygen}.mjs`, `src/v2/supervisor/owner.mjs`, `scripts/v2/run-isolated.mjs`, `scripts/v2b/run-redteam.mjs`.
- No file under `src/v5`, `src/v6`, `scripts/v5`, `scripts/v6`, `tests/v5`, `tests/v6` or existing evidence was modified. The only file added under docs is `docs/evidence/legacy-hardening/legacy-mutations.json`.

## 4. `npm test` (VERIFIED, run sequentially as root)

| Tree | tests | pass | fail | skipped | duration |
|---|---|---|---|---|---|
| HEAD c86d4f4 (`<scratch>`) | **599** | **599** | 0 | 0 | 52.3 s |
| baseline a8ce018 (disposable worktree) | 586 | 586 | 0 | 0 | ~52 s |

- The difference is exactly the 13 new tests (4 new test files). No baseline test disappeared or changed outcome (I diffed the sorted names).
- The Linux OS-principal tests ran and passed: `OS: access matrix + all 24 techniques`, `OS: containment + automated repair drill`, and `OS: V3 principal privilege matrix`.
- Logs: `review-m2-artifacts/npm-test-HEAD.tap`, `review-m2-artifacts/npm-test-a8ce018.tap`.

## 5. Mutation testing and the surviving mutant

**Branch script reproduced:** `scripts/v2/legacy-hardening-mutations.mjs` in the disposable worktree, 8/9 caught. That matches the committed `legacy-mutations.json`. Provenance nit (**F12, Info**): the JSON's `generatedBy` says `scripts/v6/reconcile-mutations.mjs`, but the file is actually written by `scripts/v2/legacy-hardening-mutations.mjs`.

**Is "#19 keygen private mode check removed" equivalent?** On POSIX-mode filesystems it is effectively equivalent. It is **not strictly equivalent**.

- The removed line is `writeNew`'s `if (mode === 0o600 && (st.mode & 0o077) !== 0) fail(...)`. It runs right after `open(O_CREAT|O_EXCL|O_NOFOLLOW, 0600)` creates a new inode. The umask can only clear bits, so the result can never have group/other bits.
  - VERIFIED: with umask 000 in a setgid, o+w directory the file mode is still 600.
  - ASSUMED, `setfacl` unavailable: POSIX default ACLs cannot add group-class bits either, because the ACL mask is ANDed with the mode's group bits (0).
  - Only the same uid or root could chmod the randomly named temp file inside the race window, and both are already trusted.
- The line *does* fire on filesystems or platforms where `fstat` reports bits that `open` did not grant: mode-ignoring mounts (vfat/exfat/ntfs/CIFS/some FUSE or 9p) and win32.
  - I simulated this with an `fstat` fault-injection shim (`det/mode.mjs`). **Patched:** the first run fails with `KEY_FILE_TOO_PERMISSIVE` and writes no key. **Mutant:** the first run **returns success with a permissive key file linked into place**. The second run's `readPrivate` check then refuses it.
  - On vfat specifically, `link()` would fail with EPERM anyway, so there the mutant only changes the error code.
- Conclusion: the line is defense in depth, and its condition cannot be reached on the Linux test filesystems. The mutant can only be killed with fs fault injection, for example a test that wraps `fstatSync`. Calling it "equivalent" is acceptable for Linux/ext4/tmpfs. It should not be described as equivalent in general.

**Additional mutants I wrote** (21 mutants, run against the 4 new test files plus `tests/v1/executor-verifier.test.mjs`). Harness and results: `review-m2-artifacts/mut-extra.mjs` and `review-m2-artifacts/mut-extra.json`. **Only 6/21 were killed.** The survivors:

| Survivor | Assessment |
|---|---|
| keygen `linkSync` -> `renameSync` | **Real test gap (F13, Medium for test strength).** The 8-process race test and my 24x15 race cannot kill it. My deterministic interleave (`det/det.mjs`) kills it: the loser overwrites the winner's private key. This is the core exclusivity property of #19 and should have a deterministic test. |
| keygen loser re-read removed (rethrow EEXIST) | Test gap. The branch's race test misses it; my 24x15 race kills it (12/360 children fail). Strengthen the race or add the deterministic interleave. |
| keygen `O_EXCL` dropped from `writeNew` | Practically equivalent (the temp name is random, and `link` still provides exclusivity). |
| keygen `ensureAppendFile` O_NOFOLLOW dropped | **Test gap.** No test plants a symlink at `owner-log.jsonl`/`labels`/`freeze` before `keygen sup`. In my kg.sh run, baseline-like behaviour (following the link) only shows up with a canary check. |
| keygen `readPrivate` isFile removed; V1 isFile removed; owner view isFile removed | Test gap. A directory gets EISDIR from `read` anyway (only the error code changes). A FIFO hangs either way (F1). |
| keygen `publishPublic` unlink removed | Equivalent (`rename` replaces the symlink), see F3. |
| `commandOnPath` interpolation / regex removed (each alone) | Each is masked by the other layer, so equivalent individually. No test covers removing both. |
| `stat` drops `--` | Equivalent while the absolute-path check holds. |
| NUL check removed | Equivalent apart from the error code (Node rejects NUL in argv itself). |
| V1 size cap removed | Test gap (no >1 MiB test), low impact. |
| owner view truncation check removed | Still throws (`ERR_OUT_OF_RANGE`), only the code changes. Test gap for the coded error. |
| **owner view torn-line cut removed** | **Real test gap (F14, Medium for test strength).** No test writes a partial trailing line. With the mutant, a partial record would be consumed and lost, and the view would desynchronise. |

## Findings summary

| # | Severity | Status | Finding |
|---|---|---|---|
| F1 | Medium (Low in 0700 deployment) | VERIFIED, regression for keygen-sens and owner view | FIFO at key/log path hangs: blocking `open` happens before the `isFile` check. Add `O_NONBLOCK`. |
| F9 | Medium (claim gap) | VERIFIED, RESIDUAL | Incremental owner-log view does not detect inode replacement or truncate+regrow (no dev/ino tracking). Forged records are accepted. |
| F13 | Medium (test strength) | VERIFIED | The keygen create-exclusivity (`link`) mutant survives the suite. A deterministic interleave kills it. |
| F14 | Medium (test strength) | VERIFIED | No partial-line test for the owner-log view. The torn-line mutant survives. |
| F8 | Low | VERIFIED, RESIDUAL | Only the final path component is protected (parent-dir symlinks followed). No owner/nlink checks (V1 loaders, keygen, owner log). |
| F2 | Low | VERIFIED, pre-existing | keygen adopts any planted regular 0600 key file (no uid check). |
| F4 | Low | VERIFIED | Newline in a file name can forge report lines (`FIND_FAILED`). Use `-print0`. |
| F5 | Low | VERIFIED, pre-existing | Symlinked root operand (e.g. node_modules) is never scanned. |
| F10 | Low | VERIFIED, pre-existing | Offset advanced before parse, so a malformed line permanently skips later records. |
| F11 | Low | ANALYSED, pre-existing | Offset is computed from decoded text and drifts on invalid UTF-8. |
| F3 | Info | VERIFIED | Unneeded `unlink` before `rename` in `publishPublic` (ENOENT window); temp file leak on `writeNew` failure. |
| F6 | Info | VERIFIED, pre-existing | Code-writability report is never enforced. |
| F7 | Info | VERIFIED | `find` output >1 MiB gives ENOBUFS (fails closed with FIND_FAILED). |
| F12 | Info | VERIFIED | `legacy-mutations.json` `generatedBy` names the wrong script. |
| §2.5 | Info | ASSUMED / NOT_RUN | win32: keygen mode checks unguarded (would always fail); O_NOFOLLOW is a no-op; new tests not win32-skipped. |

## Status inventory

- **FIXED (verified before/after):**
  - #19: symlink follow at key, pub, clock and log paths; the check-then-create race (EEXIST crash in the baseline; deterministic winner preservation).
  - #21: shell injection and silent misses via spaces, quotes, `$()`, backticks and `;`; relative/dash-led operands; find failure masking.
  - #23: final-component symlink follow and the stat-then-read TOCTOU in V1 key loaders.
  - #24: symlink at owner-log path (view and writer); size-check-then-read on a different file; negative-length crash on truncation.
- **PARTIAL:**
  - #24 incremental view (F9: no file-identity binding).
  - Path protections overall (F8: final component only).
  - Non-regular-file refusal (F1: FIFOs hang before the check).
- **RESIDUAL:** F2, F4, F5, F6, F10, F11.
- **NOT_RUN:**
  - Windows and macOS execution of any of this.
  - `scripts/v2b/run-redteam.mjs` end-to-end (syntax, exports and generated mount string only).
  - Real mode-ignoring filesystem (vfat/CIFS not available; simulated via fs shim).
  - POSIX default ACL experiment (`setfacl` not installed).
  - Contract/cargo tests (not part of `npm test`, untouched by these commits).

READY_FOR_OPERATOR_SECURITY_REVIEW. I did not merge, push, deploy or alter the recorded demo.
