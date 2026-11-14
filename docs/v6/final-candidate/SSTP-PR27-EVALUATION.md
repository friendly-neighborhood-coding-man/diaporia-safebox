# SSTP PR #27 (`d6172ec`) independent evaluation: verifySlot races

Status: **PARTIAL EVIDENCE** (unchanged). Separate from the V6 submission candidate. Nothing in PR #27 was modified.
Reviewed tree: `d6172ecccf54cd4b56f9b700a9107e45dce5d1da` (`security-fix/sstp-verifyslot`), compared with its base `c256ffa`
(PR #16). PR #28 reviewed the older PR #18 (`2707217`), not this commit. Host: Linux cloud container, Node v22.23.4,
running as root (same uid for verifier and "attacker"). MOCK files only. Date 2026-11-14.

## Method

1. **Deterministic interposition** (`tests/research/verifyslot-races.mjs`). `verifySlot` is not replaced or edited.
   `node:fs` functions are wrapped and pushed into the ESM named exports with `module.syncBuiltinESMExports()`, so the
   unmodified `install.mjs` calls the wrappers. Each wrapper performs one rename/symlink at an exact point. This
   models a concurrent same-user attacker that **wins** the race at that point. It is not a race won by timing.
2. **Real timing race** (`tests/research/verifyslot-real-race.mjs`). A separate attacker process loops
   `rename(sub, aside); rename(twin, sub); ...; rename(sub, twin); rename(aside, sub)`. `slot/sub` holds EVIL bytes
   (never matching the manifest); `twin` holds genuine bytes. Any `verifySlot` success is a bypass: it attests a slot
   whose real directory holds content that does not match the manifest.
3. **Test strength** (`tests/research/verifyslot-mutants.mjs`): remove one protection at a time, run the SSTP unit
   suite (32 tests) and the interposition probes, restore.

## Results

### Q1. File replacement after open: **closed for the window between open and the post-read check**

| Probe (d6172ec) | verifySlot | Slot at return |
|---|---|---|
| S1 file -> symlink to identical bytes after open/read, before `stillSame` | `SLOT_CONTAINS_SYMLINK` | symlink |
| S2 file -> different regular file (EVIL) after open/read, before `stillSame` | `SLOT_CHANGED_DURING_VERIFY` | EVIL |

PR #28's post-open (`fstat`-timed) symlink case on PR #18 is closed here by the post-read `stillSame` check.

### Q2. Directory replacement during recursion: **NOT closed (bypass reproduced)**

| Probe (d6172ec) | verifySlot | Slot at return |
|---|---|---|
| S4 real twin directory renamed in after `pinDir(sub)`, EVIL directory renamed back before `stillSame(sub)` | **SUCCESS** | **sub/x.mjs = EVIL** |
| S5 same, but a **symlink** to the twin | `SLOT_CONTAINS_SYMLINK` | (refused) |

`pinDir` opens the directory, checks its identity and **closes the descriptor**; `walk` then calls `readdirSync(path)`
by path. A real directory (not a symlink) swapped in for the walk and swapped back before the identity re-check
passes every check, because the children's own `realpath`/`lstat` are consistent inside the twin and the final
`lstat` of `sub` sees the original inode again.

Real timing race, 3000 `verifySlot` calls per run, 40 files in `sub/`:

| Tree | Successes while the slot held EVIL (3 runs) |
|---|---|
| `d6172ec` (PR #27) | **61, 10, 18** |
| `c256ffa` (base) | 0, 47, 10 |

The race is won by timing on both trees, at similar, noisy rates. PR #27 does not close it.

### Q3. Can the regression tests detect removal of the protections? **Mostly no (3 of 9)**

| Protection removed in d6172ec | Unit suite (32) | Interposition probes |
|---|---|---|
| `readCheckedFile` O_NOFOLLOW | **caught** (1 fail) | no change (identity check covers) |
| `readCheckedFile` O_NONBLOCK | **caught** (suite hangs on the FIFO case; timed out) | no change |
| `readCheckedFile` dev/ino identity check | **caught** (2 fail) | no change |
| read by path again (`readFileSync(p)` instead of the fd) | **not caught** | no change |
| file `stillSame` after the read | **not caught** | S1, S2 now SUCCESS |
| directory `pinDir` | **not caught** | no change |
| directory `stillSame` after the walk | **not caught** | S4 no longer swaps back (still SUCCESS) |
| `stillSame` realpath comparison | **not caught** | S5 now SUCCESS |
| top-level `stillSame(slotDir)` | **not caught** | no change |

The PR's directory test is static (it swaps before the call); its title says the mid-walk swap is covered "by
construction". Six of nine protections can be deleted with the unit suite still green.

### Q4. Remaining swap-and-swap-back races

- **S4 / real race above** (directory swap-and-swap-back with a real directory): open, reproduced.
- **S3** file replaced after its own checks while a later entry is verified: SUCCESS, slot holds EVIL at return.
- **S6** directory replaced after its own checks: SUCCESS, slot holds EVIL at return.
- S3/S6 are verify-then-use: any check that ends before the slot is used has this gap. Closing it needs the slot to
  be unwritable by the attacker (OS isolation), or a design that executes from the verified descriptors / an
  immutable snapshot, not a better `verifySlot`.
- Node has no `openat`/`fstatat`/`fdopendir`; holding directory descriptors across the walk and reading entries
  relative to them is not available in pure Node.
- Minor: under the real race some calls throw a raw `ENOENT` instead of a `SLOT_*` code. The witness wraps every
  error into `SLOT_MISMATCH`, so it still fails closed.

### Q5. OS-level isolation: **absent, NOT_RUN**

`package.json` defines `test:os` for `tests/os/*.spec.mjs`, but `tests/os/` does not exist at `d6172ec`. No uid
separation, no read-only slot, no malicious-publisher containment is implemented. Every race above assumes the
attacker can write the slot directory, which is what OS isolation would forbid. In this container the "attacker"
and the verifier are the same uid.

## Verdict

**PR #27 = PARTIAL FIX.** It closes the lstat-then-read file race and the post-open file swap (S1, S2). It does not close
directory substitution during recursion (S4, reproduced by interposition and by a real timing race), or
verify-then-use (S3, S6). Its tests do not detect removal of six of the nine protections. Remaining risk: **MEDIUM**,
conditional on same-user write access to the slot, which is the case today because OS isolation is NOT_IMPLEMENTED.
SSTP stays **PARTIAL EVIDENCE**. Nothing here supports describing SSTP as protecting the V6 submission.

Recommended next steps (research branch, not the V6 candidate): (1) add the three probes as tests that fail on each
mutant above; (2) re-verify the directory by comparing the `readdirSync` result against an entry list read through a
pinned descriptor (`/proc/self/fd/N` on Linux), or snapshot the slot into a verifier-owned directory before hashing;
(3) implement the OS-isolation tests (`tests/os`) before any claim beyond in-process evidence.

## Reproduce

```
cd secure-transition && npm ci
node tests/research/verifyslot-races.mjs "$PWD"              # interposition probes S0-S6
node tests/research/verifyslot-real-race.mjs "$PWD" 3000     # real timing race
node tests/research/verifyslot-mutants.mjs "$PWD" tests/research/verifyslot-races.mjs out.json   # edits install.mjs in place, restores; use a separate worktree
```
