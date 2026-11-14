# Legacy V1/V2 hardening replayed on the frozen V6 candidate (Mission 2)

Status: **READY_FOR_OPERATOR_SECURITY_REVIEW.** Research branch `security-research/v1v2-legacy-on-a8ce018`. The frozen
candidate `a8ce01840d79166403aec159c8c05e70bd916721` and its recorded evidence are not modified; this branch is a
disposable integration check, not a new submission candidate. MOCK only.

## What was replayed

On top of `a8ce018`, the PR #30 commits were cherry-picked without conflicts: `79f27b5`, `d254f5d`, `76c78b2`, `3ea8d12`,
`a0a8afd`, `448e3cb` (PR #19, #21, #23, #24 and the PR #28 conditions), then `c86d4f4` (mutation script). Review
follow-ups on top: `1ad6621` and `0282c0e`, plus this evidence commit. 15 files differ from `a8ce018`
(`files-changed-vs-a8ce018.txt`): legacy `src/v1`, `src/v2`, `scripts/v2`, `scripts/v2b`, their tests and this docs folder.
**No file under `src/v5`, `src/v6`, `scripts/v5`, `scripts/v6`, `tests/v5`, `tests/v6` or existing evidence changed.**

## Results

| Check | Result | File |
|---|---|---|
| `npm test` (full suite, sequential, root) | **603/603** (a8ce018: 586/586; +17 new tests, no baseline test changed outcome) | `full-suite.tap` |
| External interactor suite | 40/40 | (run in `integrations/external-interactor`) |
| V6 showcase (MOCK) | 11/11 clips pass | `showcase.log` |
| V6 real-device runner in selftest mode, attack denials | 8/8 refused | `selftest-attacks.log`, `selftest-attacks-summary.json` |
| Legacy mutation run | **13/14 caught** (was 8/9 on PR #30) | `../legacy-mutations.json`, `legacy-mutations.log` |
| Independent review | PASS_WITH_ISSUES | `INDEPENDENT-REVIEW.md` |

The selftest drives the bridge page with a headless browser and a virtual authenticator in the cloud container. Its
"REAL DEVICE AUTH" label is the runner's fixed label; no owner device was used. Real Gmail: NOT RUN.

**Reachability from V6 (review §3):** only `src/v1/authz.mjs` is imported by V5/V6, and only its unchanged
`ownerKeyId`/`rawFromKeyId` helpers. The V6 code paths are byte-identical; the only effect is the module's fs import set.

## Review findings and what was done

| Finding | Severity | Status on this branch |
|---|---|---|
| F1 FIFO at a key/log path hangs (blocking open before the isFile check) | Medium | **FIXED** in `1ad6621` (`O_NONBLOCK`, ENXIO mapped to `*_NOT_A_FILE`); test + 2 mutants caught |
| F9 incremental owner-log view not bound to one file | Medium | **FIXED** in `1ad6621` (dev:ino tracked, `OWNER_LOG_REPLACED`); test + mutant caught. Truncate-and-regrow of the same inode is caught by the size check only when the file shrank below the offset |
| F11 offset drift on invalid UTF-8 | Low | **FIXED** in `1ad6621` (cut at the last `0x0a` byte) |
| F12 wrong `generatedBy` | Info | **FIXED** |
| F13 keygen link-not-rename untested | Medium (test) | **FIXED**: deterministic interleave test; mutant caught |
| F14 torn last line untested | Medium (test) | **FIXED**: test; mutant caught |
| Surviving mutant "#19 keygen private mode check removed" | — | **Equivalent on POSIX-mode filesystems only** (new inode, umask can only clear bits); killable only with an fstat fault shim. Not claimed equivalent in general |
| F8 only the final path component is protected; no owner/nlink checks | Low | **RESIDUAL** |
| F2 keygen adopts a planted regular 0600 key (no uid check) | Low, pre-existing | **RESIDUAL** (the 0700 directory is the control) |
| F4 newline in a file name forges report lines | Low | **RESIDUAL** (fix: `-print0`) |
| F5 symlinked root operand never scanned | Low, pre-existing | **RESIDUAL** |
| F6 code-writability report never enforced | Info, pre-existing | **RESIDUAL** |
| F10 malformed line skips later records permanently | Low, pre-existing | **RESIDUAL** |
| F3 unneeded unlink before rename; temp leak on write failure | Info | **RESIDUAL** |
| F7 `find` output > 1 MiB gives ENOBUFS | Info | fails closed (`FIND_FAILED`) |
| Test gaps from the reviewer's extra mutants (ensureAppendFile O_NOFOLLOW, isFile-only removals, size cap, coded truncation error) | — | **RESIDUAL** (test strength only) |

## Behaviour differences versus a8ce018 for legitimate use (review §2)

1. keygen reuses and validates an existing private key and republishes the public file. Previously an existing key
   was skipped silently. A non-0600, non-regular, malformed or symlinked key is now an error.
2. keygen usage error: exit 1 with `KEYGEN_USAGE` (was exit 2, `usage`). Errors print only the error code. Launchers check
   only `status !== 0`.
3. keygen sup refuses symlinks at `owner-log.jsonl`, `labels.jsonl`, `freeze.jsonl`. Public files and `clock` are
   replaced by a new inode on every run.
4. A symlinked V1 `executorKeyFile` (for example pointing at a near-cli credential) now fails with
   `EXECUTOR_KEY_FILE_SYMLINK`. New codes: `*_SYMLINK`, `*_NOT_A_FILE`, `*_TOO_LARGE` (1 MiB cap), `*_SHORT_READ`.
5. The owner log view throws `OWNER_LOG_SYMLINK`, `OWNER_LOG_NOT_A_FILE`, `OWNER_LOG_TRUNCATED`, `OWNER_LOG_REPLACED`.
   With the F1 fix, a FIFO is refused instead of hanging (the a8ce018 view returned an empty view; the writer hung).
   The watchdog calls `refresh()` inside a getter, so these fail closed there.
6. Launcher reports gain a `FIND_FAILED <root> (<code>)` line when `find` fails; otherwise byte-identical on this repo.
7. `commandOnPath` returns false for names outside `[A-Za-z0-9._+-]` (all callers pass constants).

## NOT_RUN

- Windows and macOS. keygen mode checks are not win32-guarded and would always fail there; `O_NOFOLLOW` is a no-op
  there; several new tests would fail on Windows.
- `scripts/v2b/run-redteam.mjs` end-to-end.
- Real mode-ignoring filesystems (vfat/CIFS) and POSIX default ACLs (simulated or analysed only).
- Contract/cargo tests (not part of `npm test`; untouched).

## Errata in the recorded a8ce018 docs (reported, not changed)

- The evidence index lists the interactor as `external-interactor/`; it is `integrations/external-interactor/`.
- The selftest command is given as `real-device.mjs --selftest`; the working command is
  `node scripts/v6/real-device-selftest.mjs <port> <out> [flags]`.
