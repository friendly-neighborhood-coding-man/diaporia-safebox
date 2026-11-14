# SSTP verifySlot: closing the PR #27 walk races (post-video hardening, Mission 1)

Status: **SSTP stays PARTIAL EVIDENCE.** Separate from the V6 submission candidate `a8ce018` (not modified).
Branch `security-fix/sstp-fd-verifier`, on PR #31 (`fdd302c`), which is on PR #27 (`d6172ec`). MOCK files only.
Host: Linux 6.18 cloud container, ext4 `/tmp`, Node v22.23.4, as root (and the unit suite also as uid 65534).

**Bottom line.** The patch closes every rename/swap/symlink/new-entry race that lands *during the walk* (PR #27: 341
schedules, now 0). It gives **no content guarantee against anyone who can write a slot file**: a write through an
already-dirty shared memory mapping changes the bytes without changing any metadata, and the patched verifier accepts it
(independent review F1, reproduced). Content integrity after verification therefore depends on OS separation (the
attacker never had write access to the slot files), which is **NOT_IMPLEMENTED** for SSTP; only a permission probe for
one slot exists (`tests/os`).

## Result by label

| Item | Label | Evidence |
|---|---|---|
| Directory swap-and-swap-back during the walk (PR #31 S4; P1) | **FIXED** | P1 during the walk: PR #27 64, now 0 |
| File/directory replaced while later entries are verified (PR #31 S3/S6; A1, A2, A5, A9) | **FIXED** | during the walk: PR #27 58, now 0 |
| New entry created during the walk (A4); whole-slot swap (A6, P4); ancestor swap-and-swap-back (P5) | **FIXED during the walk** | during the walk: PR #27 29, now 0 |
| Same, landing in the final two inspecting calls (four for an entry inside a subdirectory) | **RESIDUAL** (closing window; this width holds only with fine-grained timestamps) | P5 10 schedules, A4 4, all others 0 before the last inspecting call. With timestamps masked (round-2 review R2-1) the window is everything after the entry's own final re-check (from call 33 of 41): 455 in-call, 365 before the last check |
| In-place content rewrite, chmod, rewrite + `utimes` (A3, A7, A8) during the walk | **PARTIAL** | 0 during the walk, but detection relies on the file's ctime (fine-grained on this kernel/fs); 9 schedules each after that file's own re-check |
| Write through an already-dirty `MAP_SHARED` mapping during the call | **NOT FIXED** (also open on PR #27) | `tests/research/review/mmap_bypass.mjs`: SUCCESS with EVIL bytes, ctime/mtime/inode unchanged; real race 1536/3000 SUCCESS, 749 with foreign bytes on immediate re-read |
| Verify-then-use after `verifySlot` returns | **RESIDUAL** (no verifier can close it) | needs the slot unwritable by the attacker |
| Second uid cannot rename/write/create/link/chmod a protected slot | **VERIFIED for this probe only** | `tests/os` 3/3: all EACCES/EPERM; 524k concurrent renames denied, 35k verifySlot calls succeed |
| `assertProtectedPath` precondition (with `expectUid`) | **FIXED** (new check) | unit + OS negative control; PR #27 accepts a slot under a directory owned by another uid |
| Unlisted or wrong-size files refused before they are read (memory exhaustion, review F5) | **FIXED** | `SLOT_FILE_SET_MISMATCH` / `SLOT_DIGEST_MISMATCH` before any read. A manifest without sizes (the parser always adds them) is capped at the package limit of 4 MiB per file (round-2 R2-2; unit test shows no large read) |
| Separated SSTP deployment (controller/app/Authority uids, launcher) | **NOT_IMPLEMENTED / NOT_RUN** | Mission 3 branch |
| Coarse-timestamp kernels/filesystems, tmpfs/overlay/NFS, ACLs, macOS/Windows | **NOT_RUN** | non-Linux fails closed (`VERIFIER_FD_RELATIVE_UNAVAILABLE`) |

## Before / after (deterministic interposition)

`tests/research/verifyslot-exhaustive.mjs` wraps `node:fs` (pushed into ESM exports with `syncBuiltinESMExports`, so
the unmodified `install.mjs` calls the wrappers), and runs the attacker's mutation immediately before fs call k (every k)
or a swap/swap-back before calls i < j (every pair). "During the walk" = the last mutation precedes the last content read.

| Attack | PR #27: during walk / in call | now: during walk / in call / before last inspecting call |
|---|---|---|
| A1 file replaced | 18 / 23 | 0 / 2 / 0 |
| A2 `sub/` replaced | 4 / 9 | 0 / 2 / 0 |
| A3 in-place rewrite (same inode) | 21 / 26 | 0 / 11 / 9 |
| A4 extra file in `sub/` | 13 / 18 | 0 / 6 / 4 |
| A5 file -> symlink | 18 / 23 | 0 / 2 / 0 |
| A6 slot dir replaced | 0 / 0 | 0 / 2 / 0 |
| A7 chmod 0664 | 22 / 27 | 0 / 11 / 9 |
| A8 rewrite + utimes | 21 / 26 | 0 / 11 / 9 |
| A9 hardlink + rename over a file | 18 / 23 | 0 / 2 / 0 |
| P1 `sub/` swap-and-swap-back (real twin) | 64 / 134 | 0 / 16 / 0 |
| P2 `sub/` swap-and-swap-back (symlink) | 0 / 0 | 0 / 0 / 0 |
| P3 file swap-and-swap-back | 126 / 161 | 0 / 16 / 0 |
| P4 whole-slot swap-and-swap-back | 8 / 16 | 0 / 10 / 0 |
| P5 ancestor swap-and-swap-back | 8 / 16 | 0 / 20 / 10 |
| **Total** | **341 / 502** | **0 / 111 / 41** |

A6–A9, P4 and P5 were added from the independent review. mmap writes are not modelled by this probe (separate
reproducer). Lines in `review-reproducers.jsonl` carry no tree label; one `before-final` line where the attack never
fired comes from the d6172ec run (the reviewer confirmed it fires and bypasses on this branch). Files: `evidence/exhaustive-d6172ec.json`, `evidence/exhaustive-new.json`, `evidence/review-reproducers.jsonl`.

## The change (`secure-transition/src/package/install.mjs`)

1. Directories are opened `O_DIRECTORY|O_NOFOLLOW`, identity-checked against their `lstat`, and held for the whole call;
   children are reached through `/proc/self/fd/<N>/<name>` (descriptor-relative on Linux; the reviewer confirmed it
   independently). Files are opened `O_NOFOLLOW|O_NONBLOCK`, identity-checked, read from the descriptor and re-`fstat`-ed.
   Unlisted or wrong-size files are refused before reading.
2. Closing pass with all directory descriptors held: every entry's dev/inode and ctime (size for files) through its
   parent descriptor; then every non-root directory's name set and mtime/ctime, deepest first; then the slot path
   (`realpath` + `lstat` identity); then the root directory last.
3. `assertProtectedPath(slot, expectUid)` when `expectUid` is given (the Witness passes `ctlUid`).
4. Fails closed without procfs semantics. The return value is unchanged (`{ files }`); the earlier
   `assurance: 'FD_RELATIVE_WITHIN_CALL'` label was removed because the review showed it over-claimed.

### What carries the protection (mutation run, `evidence/fd-mutants.json`)

25 mutants on `0a2fd75` (before the R2-2 size cap), **14 caught**. Each survivor's exposure was measured with the
exhaustive probe and compared against the unmutated baseline (111 in-call, 0 during the walk, 10 renames before the
last inspecting call):

- **Load-bearing (caught):** the closing entry re-check loop, its ctime comparison, the directory mtime/ctime check,
  the root-directory and slot-path re-checks, the openDir identity check, `O_NOFOLLOW` on file opens, all four
  protected-path checks, and three double mutants that remove the descriptor walk together with a closing check.
- **Survivor, CLOSING_WINDOW_LARGER (test gap):** reverting the review-F2 order (slot path checked after the root
  directory) keeps 0 during the walk but raises renames before the last inspecting call from 10 to 40. The unit test
  asserts the window width (2 calls), not the schedule count, so it does not catch this. RESIDUAL as a test gap.
- **Survivors, NO_EXTRA_EXPOSURE_IN_MODEL (10):** descending and listing by path, `stat` instead of `lstat`,
  `O_NOFOLLOW` on directory opens, the readAt identity and post-read checks (alone and together), root-first directory
  order, the directory name-set check, and re-checking by path without held descriptors. In this model the closing
  inode re-checks already catch what these would.
- **Defence in depth, not load-bearing in this model:** the descriptor-relative traversal itself. Descending, listing
  and even re-checking by path instead of through `/proc/self/fd` adds no measured exposure (reviewer F3 agrees). We
  therefore do **not** claim security from the descriptor-relative traversal, and not from path re-checks alone (PR #27
  had path re-checks and lost 341 schedules). The in-walk result rests on inode-identity re-checks after the whole walk
  over held directory descriptors; that part does not depend on timestamps. Timestamps (ctime/mtime) narrow the
  closing window and are the only detection of in-place rewrites, so on coarse-timestamp kernels or filesystems those
  rows degrade (reviewer's masked-timestamp model: 49 content/mode bypasses during the walk). NOT_RUN on such systems.

## Residuals

1. **Content writes by a slot writer (NOT FIXED).** Metadata cannot detect a write through an already-dirty shared
   mapping. Defensible fixes, none implemented here: (a) OS separation so no attacker ever holds a writable descriptor
   or mapping of a slot file (the installer must create files under the controller uid with the final mode, as today);
   (b) "use only the verified bytes": hash into a verifier-held copy and load/execute from that copy, a sealed `memfd`,
   or an fs-verity/immutable file. SSTP has no activation code yet (controller NOT_IMPLEMENTED), so (b) has no consumer.
2. **Closing window (RESIDUAL).** A mutation in the final two inspecting calls (four for an entry inside a
   subdirectory) gets through; this is the same class as verify-then-use.
3. **Verify-then-use (RESIDUAL).** Anything attested can be changed afterwards by a slot writer.
4. Hardlinks and empty extra directories are accepted (as before); `fdRelativeSupported` checks procfs once per call on
   one descriptor (a fake `/proc` needs mount privilege).

## Real timing races

| Run (3000 calls, 40 files) | PR #27 | this branch |
|---|---|---|
| v1 (attacker process) | 3, 0, 0 (PR #31 recorded 61, 10, 18) | 2, 1, 2 |
| v2 (attacker thread, shared rename counter) | 0, 0, 1 successes, all STABLE_GENUINE | 1, 0, 0, all STABLE_GENUINE |
| reviewer's mmap race | (same hole) | 1536 SUCCESS, 749 with foreign bytes |

The rename races do not separate the two versions by timing; the deterministic probe does. (v1/v2 runs predate the
final reordering commit, which only moved the slot-path check.)

## Tests

`npm test` 36/36 as root and as uid 65534; `npm run test:os` 3/3 (root; skipped as NOT_RUN otherwise). The new unit
spec fails on PR #27 (reviewer: 3 of 4 with export shims; the exhaustive assertion alone: 341 during-walk bypasses).

## Independent review

`INDEPENDENT-REVIEW.md` (round 1, on `48ccbcc`+): code PASS_WITH_ISSUES, within-call claim FAIL (F1 HIGH mmap, F2
MEDIUM ancestor swap, F3 MEDIUM traversal not load-bearing, F4/F5 LOW). Addressed in `3d6c254`: F2 reordered, F4 test,
F5 pre-read refusal, F1/F3 by withdrawing the claim and relabelling (F1 stays NOT FIXED).

Round 2 (`INDEPENDENT-REVIEW-ROUND2.md`, on `0a2fd75`): **PASS_WITH_ISSUES**, no regressions; F2/F4/F5 confirmed fixed
(36/36 as root and uid 65534, OS 3/3, exhaustive numbers reproduced, mmap still SUCCESS and correctly NOT FIXED).
R2-1 (closing window assumes fine-grained timestamps) and R2-3 (total 41, not 50) fixed in this document; R2-2 (no
size cap for a manifest without sizes) fixed in code with a test that fails without the fix; R2-4/R2-5 noted;
R2-6 (`readCheckedFile` exported but unused by `verifySlot`) left as is.

## Follow-up security video (optional, only after operator review)

Terminal-only, MOCK, no owner device: (1) `node tests/research/verifyslot-exhaustive.mjs` on a `d6172ec` checkout and on
this branch (341 vs 0 during the walk); (2) `npm run test:os` showing EACCES for the second uid; (3) the mmap reproducer,
shown as the remaining NOT FIXED item. Not recorded; nothing in the V6 videos changes.

## Reproduce

```
cd secure-transition && npm ci
npm test && npm run test:os
node tests/research/verifyslot-exhaustive.mjs "$PWD" out.json        # and against a d6172ec checkout
node tests/research/review/mmap_bypass.mjs "$PWD" after-read          # needs python3
node tests/research/review/ancestor_swap.mjs "$PWD"
node tests/research/verifyslot-real-race-v2.mjs "$PWD" 3000
node tests/research/verifyslot-fd-mutants.mjs "$PWD" mutants.json    # edits install.mjs in place; use a spare worktree
```
