# SSTP verifySlot: closing the PR #27 walk races (post-video hardening, Mission 1)

Status: **SSTP stays PARTIAL EVIDENCE.** Separate from the V6 submission candidate `a8ce018` (not modified).
Branch `security-fix/sstp-fd-verifier`, on PR #31 (`fdd302c`), which is on PR #27 (`d6172ec`). MOCK files only.
Host: Linux 6.18 cloud container, ext4 `/tmp`, Node v22.23.4, running as root.

## Result by label

| Item | Label | Evidence |
|---|---|---|
| Directory swap-and-swap-back during the walk (PR #31 S4) | **FIXED** (in-call) | exhaustive probe P1: PR #27 64 successes with a foreign slot during the walk, now 0 |
| File / directory replaced while later entries are verified (PR #31 S3, S6) | **FIXED** (in-call) | probes A1, A2, A5: PR #27 40 during-walk bypasses, now 0 |
| In-place rewrite of a file (same inode) during the walk | **FIXED** (in-call) | probe A3: PR #27 21, now 0 |
| New entry created during the walk | **FIXED** (in-call) | probe A4: PR #27 13, now 0 |
| Symlink swap-and-swap-back | still refused (was refused) | probe P2: 0 successes on both |
| Mutation after the verifier's final check of that object, before `verifySlot` returns ("closing window", the last few calls) | **RESIDUAL** | 53 of 3,053 schedules (1,926 fired fully), all in the closing window; see below |
| Verify-then-use after `verifySlot` returns | **RESIDUAL** (not addressable by any verifier) | needs the slot to be unwritable by the attacker |
| Slot unwritable by a second uid when owned by the verifier uid and the path is protected | **VERIFIED for this probe only** | `tests/os`, 3/3: every rename/write/create/symlink/chmod from uid 65534 gives EACCES/EPERM; 524k concurrent rename attempts denied, 35k verifySlot calls all succeed |
| Precondition check `assertProtectedPath` (slot and ancestors not writable by others; sticky ancestors allowed) | **FIXED** (new check, only when `expectUid` is given) | unit + OS negative control; PR #27 accepts a slot under a directory owned by another uid |
| Separated SSTP deployment (controller/app/Authority uids, launcher) | **NOT_IMPLEMENTED / NOT_RUN** | see the Mission 3 branch |
| Non-Linux hosts | fails closed: `VERIFIER_FD_RELATIVE_UNAVAILABLE` | **NOT_RUN** on macOS/Windows |

## The defect, reproduced

`tests/research/verifyslot-exhaustive.mjs` wraps `node:fs` (pushed into the ESM exports with
`module.syncBuiltinESMExports()`, so the unmodified `install.mjs` calls the wrappers), counts every fs call
`verifySlot` makes on an untouched 3-file slot, and runs the attacker's mutation immediately before call k (every k), or
a swap and a swap-back before calls i and j (every pair i < j). A success whose slot does not match the manifest at
return is an in-call bypass; one whose last mutation precedes the last content read is a bypass **during the walk**.

| Attack | PR #27 `d6172ec`: bypass during walk / in call | this branch: during walk / in call |
|---|---|---|
| A1 file replaced by an EVIL file | 18 / 23 | 0 / 2 |
| A2 `sub/` replaced by an EVIL directory | 4 / 9 | 0 / 2 |
| A3 file rewritten in place (same inode, same length) | 21 / 26 | 0 / 11 |
| A4 extra file created in `sub/` | 13 / 18 | 0 / 4 |
| A5 file replaced by a symlink to genuine bytes | 18 / 23 | 0 / 2 |
| P1 `sub/` swap-and-swap-back with a real genuine twin | 64 / 134 | 0 / 16 |
| P2 same with a symlink | 0 / 0 | 0 / 0 |
| P3 file swap-and-swap-back | 126 / 161 | 0 / 16 |
| **Total** | **264 / 394** | **0 / 53** |

Files: `evidence/exhaustive-d6172ec.json`, `evidence/exhaustive-new.json`.

## The change (`secure-transition/src/package/install.mjs`)

1. **Descriptor-held walk.** Every directory is opened `O_DIRECTORY|O_NOFOLLOW`, checked against its `lstat`
   (dev/inode) and kept open for the whole call; children are listed and reached through
   `/proc/self/fd/<N>/<name>`, a procfs magic link that looks the name up inside the directory descriptor N holds. Files
   are opened `O_NOFOLLOW|O_NONBLOCK`, identity-checked, read from the descriptor, and `fstat`-ed again after the read
   (size and ctime unchanged).
2. **Closing re-check pass**, all directory descriptors still held: every entry's dev/inode and ctime (and size for
   files) is re-checked through its parent descriptor; the slot path must still resolve to the walked root; then every
   directory's name set and mtime/ctime are re-checked, deepest first, root last. A rename into, out of or within a
   directory, including swap-and-swap-back, changes that directory's mtime/ctime.
3. **`assertProtectedPath(slot, expectUid)`**, when `expectUid` is given (the Witness passes `ctlUid`): the slot and
   every ancestor must be real directories owned by root or `expectUid`, with no group/other write (an ancestor may be
   group/other-writable only with the sticky bit, like `/tmp`).
4. `fdRelativeSupported()` is checked on every call; without procfs semantics the verifier refuses
   (`VERIFIER_FD_RELATIVE_UNAVAILABLE`) instead of falling back to path checks.

Return value gains `assurance: 'FD_RELATIVE_WITHIN_CALL'`. Error codes are unchanged except the three new ones
(`SLOT_PATH_NOT_PROTECTED`, `VERIFIER_FD_RELATIVE_UNAVAILABLE`, `SLOT_TOO_MANY_DIRECTORIES` above 4096 directories).

### What actually carries the guarantee (from the mutation run)

Removing one layer at a time (`evidence/fd-mutants.json`, 23 mutants incl. 4 double mutants) and measuring both the
tests and the exhaustive-probe exposure:

- **Load-bearing:** the closing entry re-check (removing it: 15 bypasses during the walk), its ctime comparison (15),
  the directory mtime/ctime check (244 rename schedules before the last check), the deepest-first ordering (20), and
  the four protected-path checks. All are caught by the tests.
- **Redundant in this model (11 survivors, none adds exposure):** descending by path instead of the descriptor,
  listing by path, `lstat` vs `stat` for children, `O_NOFOLLOW`/identity checks in `openDir`, the identity and post-read
  checks in `readAt`, the name-set comparison, the slot-path re-check and re-checking by path in the closing pass.
  The descriptor-relative traversal is therefore **defence in depth, not shown to be load-bearing** by this model:
  the in-walk guarantee comes from re-checking every entry's identity after all content was read, through directory
  descriptors held since the walk. We do not claim more for it than that.
- **Not security from path rechecks alone:** PR #27 already re-checked paths and lost 264 schedules; the difference
  is the closing pass over held descriptors after the whole walk, plus directory timestamps for the closing window.

Directory timestamps narrow the closing window only. The in-walk result (0) holds without them (mutant: 0 during the
walk, more in the closing window). Timestamp granularity: ext4 on Linux ≥ 6.13 records fine-grained ctime/mtime after
a query; on filesystems with coarse timestamps two changes in one tick may look identical. That affects the closing
window, not the in-walk result. NOT_RUN on other filesystems.

## Residuals (unchanged in kind, smaller in size)

- **Closing window (RESIDUAL).** All 53 remaining in-call successes need the mutation to land after the final check
  that covers the mutated object: renames only after the root directory's last check (only descriptor closes follow);
  an extra file in `sub/` after `sub/`'s last check (the root's 2 final calls remain); an in-place rewrite after that
  file's own re-check. This is the same class as verify-then-use.
- **Verify-then-use (RESIDUAL).** Whatever `verifySlot` attests can be changed afterwards by anyone who can write the
  slot. Only OS separation closes this: the slot, its ancestors, the marker and the staged archive must be unwritable
  by the application and the candidate. `assertProtectedPath` checks the permission half; the separated deployment is
  NOT_IMPLEMENTED.
- **Same-uid attacker.** A same-uid attacker can also change permissions and ownership checks are meaningless. With
  `expectUid` and a different attacker uid, `tests/os` shows the kernel refuses every write attempt.

## Real timing races

| Run (3000 calls each, 40 files) | PR #27 | this branch |
|---|---|---|
| v1 (attacker process; cannot tell why a call succeeded) | 3, 0, 0 (PR #31 recorded 61, 10, 18) | 2, 1, 2 |
| v2 (attacker thread with a shared rename counter) | 0, 0, 1 successes, all STABLE_GENUINE | 1, 0, 0 successes, all STABLE_GENUINE |

v2 classifies each success: STABLE_GENUINE means no rename happened during the call (the genuine twin sat in the slot
for the whole call), so it is not a bypass. No FOREIGN_AT_RETURN success on either tree. Timing races are noisy; the
deterministic probe is the primary evidence.

## Tests

- `npm test` 36/36 (32 existing + 4 new in `tests/unit/verifyslot-fd.spec.mjs`, which runs the exhaustive probe and
  requires 0 bypasses during the walk and renames only after the last inspecting call).
- `npm run test:os` 3/3 (new `tests/os/verifyslot-uid.spec.mjs`; needs root to start uid 65534; skipped as NOT_RUN
  otherwise). Non-destructive probes on MOCK files only. On PR #27 the same file gives 2/3: the negative control fails
  because PR #27 accepts a slot under a directory owned by the other uid.
- Mutation: 12/23 caught; the 11 survivors are the redundant layers listed above (classified by measured exposure).

## Reproduce

```
cd secure-transition && npm ci
npm test && npm run test:os
node tests/research/verifyslot-exhaustive.mjs "$PWD" out.json        # also against a d6172ec checkout
node tests/research/verifyslot-real-race.mjs "$PWD" 3000
node tests/research/verifyslot-real-race-v2.mjs "$PWD" 3000
node tests/research/verifyslot-fd-mutants.mjs "$PWD" mutants.json      # edits install.mjs in place; use a spare worktree
```

## Independent review

See `INDEPENDENT-REVIEW.md` in this directory.
