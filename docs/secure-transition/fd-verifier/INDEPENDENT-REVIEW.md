# Independent security review: SSTP `verifySlot` descriptor-relative patch (Mission 1)

Reviewed tree: `<scratch>` branch `security-fix/sstp-fd-verifier`, HEAD `057fc5a` (patch commits `48ccbcc`, `057fc5a`; base `d6172ec` = PR #27).
Host: Linux 6.18.44, ext4 root (`/tmp` and `/opt/wt` on the same ext4 filesystem), Node v22.23.4, running as root. MOCK files only, no network.
I did not edit the reviewed worktree. All experiments ran on copies in `<review-scratch>/` (scripts kept there as reproduction evidence). `<scratch>` was not touched.

## Verdict

**PASS_WITH_ISSUES for the code change. FAIL for its assurance claim.**

- The code change is a strict improvement over PR #27 and introduces no security regression I could find. Under deterministic interposition, every rename, swap and symlink attack that lands during the walk is now refused (0 bypasses during the walk, against 0 to 161 per attack class for PR #27). No descriptor leaks on any error path. Unsupported platforms fail closed. Performance is unchanged.
- The claim that the change "bounds every check to the end of the verifySlot call" (and the `assurance: 'FD_RELATIVE_WITHIN_CALL'` label) does not hold. I built a deterministic bypass and a real race in which verifySlot returns SUCCESS while the slot holds EVIL bytes, and the mutation happens before the verifier's post-read check and its whole final pass (F1). A second deterministic bypass lands before the final directory checks (F2). Separately, the descriptor-relative traversal named in the title does not carry the security the tests measure (F3).
- What the patch fixes should be labelled **FIXED (within the interposition model, on this kernel)** only for namespace races during the walk: swap-and-swap-back of `sub/` or a file, symlink swaps, persistent replacement. Content integrity within the call is **NOT FIXED** against a same-uid attacker. Verify-then-use is **RESIDUAL**, as documented.

## Findings

### F1. HIGH: a write through a shared memory mapping changes file content during the call without changing any metadata, so verifySlot returns SUCCESS on EVIL bytes
The verifier detects in-place changes only through `ctime`/`size`/inode: the post-read `fstat` and the entry re-check in the final pass. On Linux, writing to a page of a `MAP_SHARED` mapping that is already dirty updates neither mtime nor ctime. Timestamps change only when the page faults writable again after writeback. A same-uid attacker who holds a writable mapping of a slot file (and dirtied the page at any earlier time, including before the call) can rewrite the bytes after verifySlot has read them. Nothing the verifier inspects changes. This is not limited to a closing window: the mutation can land right after `readFileSync`, before the post-read `fstat` and before the whole final pass.

What I checked:
- `ts.py`: a write to a dirty mmap page left `ctime` and `mtime` unchanged on this ext4 host.
- `mmap_bypass.mjs` (deterministic, fs interposition plus a python helper holding the mapping):
  - `after-read`: `{"verifySlot":{"files":3,"assurance":"FD_RELATIVE_WITHIN_CALL"},"aMjsAtReturn":"export const ok = \"EVIL!!!\";","matchesManifest":false,"ctimeUnchanged":true,"mtimeUnchanged":true,"inoUnchanged":true}`
  - `before-final` (mutation placed before the first final-pass entry `lstat`): same result, SUCCESS.
  - PR #27 tree: the same bypass works.
- `mmap_race.mjs` (real race, no interposition; a python process flips the bytes through the mapping in a tight loop): 3000 calls gave `SUCCESS 1522`, `SLOT_DIGEST_MISMATCH 1478`, **0 `SLOT_CHANGED_DURING_VERIFY`**, and 744 successes where an immediate re-read showed foreign bytes. The file's ctime stayed unchanged for the whole run. The change-detection layer never fired.

Reproduce:
```
cd <review-scratch>
node mmap_bypass.mjs <candidate> after-read
node mmap_bypass.mjs <candidate> before-final
node mmap_race.mjs  <candidate> 3000
```
Impact: against a same-uid attacker the patch gives no content guarantee within the call. In practice the attack adds little, because a same-uid attacker can always write after the call returns. But it falsifies the stated within-call bound and the test's statement that the in-place rewrite (A3) "is bounded by that file's own entry re-check".

With `expectUid` set, a different uid needs a writable descriptor or mapping that it already held, because DAC is checked at open time. A process that ever had write access to the file (for example the installer uid, or anyone during a window when the mode was looser) can keep that access forever. Not testing `nlink`, open-writer state or file seals leaves this undetectable.

Fix direction: metadata cannot detect this. Either use exactly the verified bytes (hash, then load or execute from the verifier-held copy, or from a sealed `memfd` or an fs-verity/immutable file), or rely on OS separation where no attacker ever had a writable descriptor. Relabel the assurance accordingly.

### F2. MEDIUM: an ancestor swap-and-swap-back after the final slot-path check, but before the final directory checks, is accepted
The final pass runs in this order: entries, then the slot path (`realpath` plus `lstat` identity), then every directory with the root last. Renaming an ancestor of the slot changes no mtime or ctime of any directory the verifier holds. So once the slot-path check has run, an attacker can swap the ancestor back, and the remaining `readdir`/`fstat` calls (2 per directory) still see the genuine twin through the held descriptors.

- Interposition (my added attack P5 in `ex2.mjs`): 30 bypassing schedules, 20 of them before the last inspecting call (`1+38:openSync+readdirSync` … `5+41:lstatSync+fstatSync`).
- Standalone reproduction `ancestor_swap.mjs`: `{"fired":true,"verifySlot":{"files":2,"assurance":"FD_RELATIVE_WITHIN_CALL"},"aMjsAtReturn":"EVIL!!!"}`.
- The window grows with the number of directories in the slot (up to about 256 with the tar limits).

This contradicts the unit-test comment that "for those attacks a foreign slot only gets through if the mutation lands after the verifier's LAST inspecting call". The exhaustive suite never models ancestor or whole-slot renames.

I tried moving the slot-path block after the directory loop (copy in `st-reorder-experiment/`). P5 then drops to the closing window only (0 before the last check). But the A1/A2/A5/A9 classes then get 2 calls before the last check, and one existing assertion fails. Suggested order: non-root directories deepest-first, then the slot path, then the root `readdir`/`fstat` last.

Only relevant without `expectUid`, or for an attacker that may write an ancestor. With `expectUid`, `assertProtectedPath` keeps a different uid out of the ancestors.

### F3. MEDIUM: the descriptor-relative traversal does not carry the measured security; timestamps do, and they are fine-grained only on recent kernels
- Combined mutant (`mut-all-path-lookups/`): I replaced every `/proc/self/fd/<N>/<name>` lookup in the walk and in the final pass with a lookup by slot path, keeping only the `fstat` of held directory descriptors. All 36 unit tests pass. Exhaustive exposure is unchanged except P5 (36 vs 30), and P1 is 16 vs 16. The author's own `fd-mutants.json` shows the same: 11/23 mutants survive as `NO_EXTRA_EXPOSURE_IN_MODEL`, including "walk descends by slot PATH instead of the parent descriptor" and "final pass re-checks … by slot PATH".
- In this design the protection comes from the inode identity re-checks plus directory mtime/ctime on held descriptors. I masked all timestamps to model a coarse or unchanged tick (`COARSE=1 node ex2c.mjs`). The patched verifier then has 475 bypasses (49 during the walk, all content or mode: A3/A7/A8), with P1 at 160 and 128 of those before the last check. The all-path mutant has 470. The fd-relative walk adds nothing measurable in either model.
- This host (6.18, ext4) gives fine-grained ctime after a `stat` (multigrain timestamps). On kernels or filesystems that only record the coarse (jiffy) tick (I am assuming kernels older than about 6.13; see NOT_RUN), a swap-back or in-place write that lands in the same tick as the verifier's `fstat` leaves mtime/ctime unchanged. The masked model shows that the patch then gives no protection within the call beyond the inode re-check.
- The mission rule "do not claim security from path rechecks alone" therefore needs care. The claim really rests on metadata rechecks (identity plus timestamps). The descriptor-relative walk is defense in depth that no test exercises. No test fails if it is removed.

### F4. LOW: regression: the unit suite fails when run as non-root
As root, `npm test` gives 36/36. Run as uid 65534 on a copy, it gives 35/36: `install-journal.spec.mjs` "verifySlot detects tampering after install" expects `SLOT_WRONG_OWNER` for `expectUid: 4242` but gets `SLOT_PATH_NOT_PROTECTED` (slot owned by 65534). PR #27 passes 32/32 as non-root. The new error code fails closed and is correct, but the old assertion is stale, and the green result reported for the suite depends on running as root, where root-owned ancestors are accepted.

### F5. LOW: unbounded reads and an unbounded entry count let a planted file exhaust memory
`readAt` reads every regular file in full before the manifest comparison, with no size cap (the manifest limit is 4 MiB per file) and no cap on the number of entries. Every buffer stays in `found` until the end. A sparse file of about 1.9 GiB is read into memory. Above 2 GiB, Node throws `ERR_FS_FILE_TOO_LARGE`, which is not a `PackageError` (it fails closed, but with a non-SSTP code). Many planted files exhaust memory the same way. PR #27 behaves the same. Suggested fix: refuse an unknown name or `size > maxFileBytes` before reading.

### F6. LOW/INFO: `fdRelativeSupported()` checks procfs once, on one descriptor number
In a private mount namespace (`unshare -m`), I mounted a tmpfs over `/proc` with `/proc/self/fd/N -> /` links. `fdRelativeSupported()` returned `true`, and verifySlot then walked `/` instead of the slot (here it happened to fail with `SLOT_CONTAINS_SYMLINK`). This needs mount privilege in the verifier's namespace, so it is out of the stated threat model. A cheap hardening: compare `stat(/proc/self/fd/<dfd>)` with `fstat(dfd)` for every held directory, and use `/proc/thread-self` or `openat2`-style checks if a native helper is ever added. Results: `/proc` replaced by an empty tmpfs gives `VERIFIER_FD_RELATIVE_UNAVAILABLE` (fails closed, correct). `hidepid=2` has no effect, because `/proc/self` stays visible.

### F7. INFO: behaviour differences for legitimate slots and error codes (old vs new, `battery.mjs`)
Identical outcomes in 17 of 19 static cases. The differences:
- (a) The return value gains `assurance`.
- (b) With `expectUid`, a group/other-writable or foreign-owned slot or ancestor is now refused (`SLOT_PATH_NOT_PROTECTED`). This is intended.
- (c) An extra file with a non-UTF-8 name now gives `SLOT_CHANGED_DURING_VERIFY` instead of a raw `ENOENT`. Node decodes the name lossily and the lookup misses. It fails closed, but the code is misleading. Manifest names are ASCII (`SEGMENT`), so no aliasing is possible.
- (d) Deep trees: PR #27 is quadratic (`realpath` per entry). A 1900-level empty chain did not finish within 60 s on PR #27 and took 151 ms on the patch.
- (e) More than 4096 directories gives `SLOT_TOO_MANY_DIRECTORIES`.
- (f) Extra empty directories and hardlinked files (`nlink` 2) are accepted by both versions. The manifest does not describe directories.

Descriptor leak count after every case, including every refusal path: 0. Performance on a 256-file / 32-directory slot: 8.11 ms per call (new) vs 8.58 ms per call (old).

### F8. INFO: `assertProtectedPath`
The logic is correct for the stated purpose. Owner must be root or `expectUid`. No group/other write, except on a sticky ancestor, and never on the slot itself. Symlinked components are refused. Mutants on all four rules are caught.

Notes:
- It runs once, by path, before the walk, and is not re-checked. TOCTOU is possible only for root or `expectUid`, who are trusted, so this is acceptable.
- ACL write grants show up in the group mode bits (the ACL mask), so they are covered. I could not test this because `setfacl` is not installed.
- It does not cover descriptors or mappings that were already open (see F1), mount points, or `CAP_DAC_OVERRIDE` holders.

### F9. INFO: quality of the tests
- The new unit spec fails on PR #27. I ran it against a copy of `d6172ec` with export shims: 3 of 4 tests fail. The meaningful failure is the exhaustive test (bypasses during the walk). The others fail trivially (the new label, and the new `assertProtectedPath`).
- Weaknesses:
  - (i) "closing window" in the exhaustive harness means everything after the last `readFileSync`, which is the entire final pass (14 of 43 calls). The stricter `bypassBeforeLastCheck` assertions are the ones that matter.
  - (ii) A3 is exempted, and no ancestor, whole-slot, chmod or mmap attacks are modelled. Adding A6/A7/A8/A9/P4/P5 (`ex2.mjs`) found F2.
  - (iii) The interposition places the attacker only at fs-call boundaries, so it cannot model coarse timestamps or mmap.
  - (iv) The real-race v2 script does not discriminate: 0 `FOREIGN_AT_RETURN` for both PR #27 and the patch in my 3000-iteration runs, and in the stored `real-race-v2.jsonl`.
  - (v) No test fails if the descriptor-relative lookups are removed (F3).
- Residual descriptions: verify-then-use after return is described correctly. The "closing window" residual is described too narrowly, because of F1, F2 and F3.

### F10. INFO: the OS-level test is fair and non-destructive, and proves only discretionary access control (DAC)
- Uid 65534, without capabilities, gets EACCES/EPERM on 7 operations against a root-owned 0755 slot. A 3 s rename loop got 0 renames in (378k denied) while 27k verifySlot calls succeeded.
- The negative controls work: a probe-owned `sub/` gives `SLOT_WRONG_OWNER`, and a probe-owned slot gives `SLOT_PATH_NOT_PROTECTED`.
- All operations target its own mkdtemp tree. The symlink test only creates a link to `/etc/hostname` and does not touch `/etc`.
- What it proves: Linux DAC denies a different uid write access to this slot. It does **not** exercise any race, because the attacker never gets a write in, so verifySlot is never raced. It does not cover an attacker holding a descriptor or mapping it opened earlier (F1), or group or ACL cases. Its header comments state these limits correctly. They should not be cited as race evidence.

## Answers to the five questions
1. **Yes**: on this host the `/proc/self/fd/N/name` lookup is descriptor-relative (`q1.mjs`). After renaming the opened directory away and putting an impostor at its old path, a lookup through the descriptor still returns `ORIG`. Same after a second rename plus a symlink at the old path. A deleted directory reads empty and refuses creation. Caveat: Node's JS `realpathSync` on such paths is lexical. verifySlot does not use it on `/proc` paths.
2. **Yes**: F1 (mmap, deterministic and real race, mutation before the post-read check and the final pass) and F2 (ancestor swap before the final directory checks). The other vectors are refused or limited to the closing window: hardlink+rename (A9), utimes after rewrite (A8, because ctime still changes), entries added and removed (directory mtime), symlink swap (P2, never accepted), `O_PATH` (not available in Node, and irrelevant), very deep or wide trees (fail closed), and name joining with '/' (injective, since names cannot contain '/' or NUL). A same-uid process can reset mtime with `utimes`, but not ctime (that needs `CAP_SYS_TIME`). Bind mounts need privilege. Sticky-bit logic and uid-0 acceptance: correct (F8). Coarse timestamps: F3.
3. Regressions: F4 (non-root suite), F5 (DoS, pre-existing), F7 (error codes). No descriptor leaks. Non-Linux or missing `/proc` fails closed with `VERIFIER_FD_RELATIVE_UNAVAILABLE`, so `installToSlot` cannot work on macOS. No performance regression.
4. The tests are partly meaningful. They fail on PR #27 and catch 12 of 23 mutants. They do not test the headline mechanism, and the residual descriptions are too narrow (F9).
5. The OS test is fair and non-destructive. It proves DAC denial for one slot in this container and nothing about races or deployment (F10).

## Verified vs assumed
- **Verified on this host:** every result quoted above (scripts in `<review-scratch>/`): `npm test` 36/36 and `npm run test:os` 3/3 as root; non-root suite 35/36; mmap bypass and race; ancestor bypass; extended exhaustive runs on new, old, reorder and all-path-mutant trees; masked-timestamp model; `/proc` replacement in a private mount namespace; leak, performance and static battery.
- **Assumed or NOT_RUN:**
  - Behaviour on kernels or filesystems that record only coarse timestamps (pre-multigrain kernels, roughly before 6.13). Only the masked-timestamp model was run; no real coarse-timestamp race.
  - tmpfs, overlayfs, NFS and FUSE semantics.
  - mmap on filesystems other than ext4.
  - ACLs (`setfacl` not installed).
  - Non-Linux platforms (fail-closed result taken from code reading plus the `/proc`-less run).
  - I did not re-run the mutation tool myself (another process was using `<scratch>`). I read the stored `<scratch>` and ran one combined mutant myself.

## Must-fix before operator review
1. Downgrade the within-call claim and the `FD_RELATIVE_WITHIN_CALL` label. Content is not protected against same-uid writers (F1). Either use exactly the verified bytes, or state that the guarantee needs OS separation and that no attacker ever held a writable descriptor.
2. Reorder the final pass so that the root directory check is last and the slot-path check comes just before it, and add P5 and A6 to the exhaustive suite (F2).
3. Add a test that fails when the descriptor-relative lookups are removed, or stop presenting them as the load-bearing mechanism. Document the fine-grained-timestamp dependency, and record coarse-timestamp kernels as NOT_RUN (F3).
4. Fix the stale `SLOT_WRONG_OWNER` assertion, and run the suite as non-root as well (F4).
