# Independent security review, round 2 (delta): SSTP `verifySlot`

Reviewed: `<branch-worktree>` branch `security-fix/sstp-fd-verifier`, HEAD `0a2fd75` (code and tests in `3d6c254`, docs in `0a2fd75`). Delta reviewed with `git diff 057fc5a HEAD` (code) and `48ccbcc..HEAD` (everything).
Same host as round 1: Linux 6.18.44, ext4, Node v22.23.4. MOCK only. Nothing in `<branch-worktree>` was edited, and `<mutation-worktree>` was not touched. My runs were sequential, single-process jobs in `<review-scratch>/` and `<tmp>/rv-*` (removed afterwards).

## Verdict: PASS_WITH_ISSUES

- F2, F4 and F5 are fixed as claimed. F5 holds in production because every manifest that reaches verifySlot has `size`.
- The new pre-read check adds refusals only. I found no bypass and no wrong-error regression.
- The code comments no longer over-claim.
- The main doc is accurate in substance. Two corrections are needed: one wrong total in the before/after table, and the closing-window residual is stated without its fine-grained-timestamp condition. Neither changes a security label, but the second one matters if anyone deploys on an older kernel.

## 1. Fixes and regressions (own runs)

| Check | Result |
|---|---|
| `npm test` as root | 36/36 |
| `npm test` as uid 65534 (copy of the tree, `setpriv`) | **36/36** (round 1: 35/36). **F4 FIXED.** |
| `npm run test:os` (root) | 3/3 |
| Exhaustive interposition (the repository's updated script, HEAD) | 0 bypasses during the walk. 111 bypasses within the call, 41 before the last inspecting call (#41). The evidence file `exhaustive-new.json` gives the same totals. |
| P5 ancestor swap-and-swap-back | was 20 schedules before the last check; now 10, all at calls 40/41 (the root `readdir`/`fstat`, the last two inspecting calls). **F2 FIXED** as far as it can be: what remains is the closing window. `ancestor_swap.mjs` still returns SUCCESS with EVIL bytes, because its hook fires after the slot-path `lstat`, which is now inside that window. This is the documented RESIDUAL, not a regression. |
| A4 extra file in `sub/` | before the last check: 2 schedules went to 4 (calls 38–41). This is the expected cost of moving the slot-path check between `sub/`'s check and the root's. It is documented and asserted (`window = 4`). |
| A1/A2/A5/A6/A9, P1–P4 | 0 before the last check (unchanged) |
| mmap reproducer (`after-read` and `before-final`) on HEAD | both return SUCCESS with EVIL bytes, metadata unchanged. Still **NOT FIXED**, and labelled so. |
| Battery of static cases (24 cases, with and without `size` in the manifest, plain verify and with `expectUid`) | every outcome matches round 1. Descriptor leaks 0 on every path. |
| Unlisted 2.1 GB sparse file | `SLOT_FILE_SET_MISMATCH` before any read (was `ERR_FS_FILE_TOO_LARGE`) |
| Listed file grown to 1.9 GB (sparse), sized manifest | `SLOT_DIGEST_MISMATCH` in 0 ms, peak RSS of the run 72 MB. **F5 FIXED.** |
| Same, manifest **without** `size` | file read in full: 6.7 s, peak RSS 2017 MB. See R2-2. |

## 2. The new pre-read check (`listed` / `size`)
- It only adds `fail(...)` paths before `readAt`. The final `found.size === manifest.files.length` check and the per-file digest and mode checks are unchanged. So it cannot turn a refusal into a success.
- I checked the order of the checks:
  - The symlink and special-file checks and the mode/owner check (`meta`) still run before the unlisted check. A group/other-writable unlisted file still gives `SLOT_WRITABLE_BY_OTHERS`, and an unlisted symlink gives `SLOT_CONTAINS_SYMLINK`.
  - An unlisted FIFO next to a tampered file gives `SLOT_SPECIAL_FILE`, as before.
  - A size mismatch maps to `SLOT_DIGEST_MISMATCH`, which is what a size difference produced before.
  - A missing file still gives `SLOT_FILE_SET_MISMATCH`.
- Lookups use a `Map` with exact keys, so there are no prototype-key issues. Manifest names are ASCII, so lossy decoding of non-UTF-8 names cannot alias a listed name; such names still fail closed with `SLOT_CHANGED_DURING_VERIFY`.

## 3. Doc and comment claims

`install.mjs` comments: accurate.
- The `assurance` label is gone.
- "gives NO content guarantee against anyone who can write a slot file", the mmap note, "in-place writes … detected only through ctime … fine-grained timestamps", verify-then-use, and "/proc/self/fd traversal is defence in depth" are all consistent with my measurements.
- The final-pass order comment matches the code: entries, then non-root directories deepest first, then the slot path, then `dirCheck(dirs[0])`, and `dirs[0]` is the root.

`SSTP-VERIFYSLOT-FD.md`: labels are correct.
- mmap: NOT FIXED.
- In-place rewrite, chmod, rewrite plus utimes: PARTIAL.
- Verify-then-use: RESIDUAL.
- Separated deployment: NOT_IMPLEMENTED/NOT_RUN.
- Coarse timestamps, other filesystems, ACLs, non-Linux: NOT_RUN.
- OS probe: "VERIFIED for this probe only".

I checked two statements with my own runs:
- "PR #27: 341 … now 0": matches the evidence and my run.
- "The in-walk result … does not depend on timestamps": with all timestamps masked on HEAD (`COARSE=1 node ex-head-coarse.mjs`), the rename, swap and symlink classes still have 0 bypasses during the walk. Only A3/A7/A8 (content and mode) have 49.

## Findings

**R2-1. LOW (doc, labelling): the closing-window residual omits its timestamp condition.**
The RESIDUAL row ("landing in the final two inspecting calls, four for an entry inside a subdirectory") and the unit-test assertion hold only where mtime/ctime are fine-grained.
- With timestamps masked on HEAD, the window becomes everything after that entry's own final re-check. Earliest bypassing call per class: A1/A5/A9 #33, A2/P1 #34, P3 #33, A4 #37, of 41.
- Totals in that model: 455 bypasses within the call, 365 before the last inspecting call.
- The doc's "Timestamps … narrow the closing window" sentence and the NOT_RUN row point at this, but the RESIDUAL row reads as unconditional.
- Fix: add "on filesystems with fine-grained timestamps (this host); otherwise any time after the entry's own final re-check. NOT_RUN on coarse-timestamp systems."

**R2-2. LOW: the F5 size check is skipped when the manifest has no `size`.**
`if (mf.size !== undefined && …)` lets a manifest without `size` fall back to reading the full file (measured: 2 GB peak RSS). Production callers (`installToSlot` with `pkg.manifest`, and the Witness with `openPackage(...).manifest`) always pass `size`, because `manifest.mjs` enforces the field set `mode,path,sha256,size`. Only research and test manifests omit it.
- Fix: refuse a manifest entry without `size`, or always cap reads at `LIMITS.maxFileBytes`.
- Doc: label F5 "FIXED for parsed manifests".

**R2-3. LOW (doc, numbers): the before/after table total is wrong.**
The total row says "0 / 111 / **50**". The per-row values (9 + 4 + 9 + 9 + 10) and `evidence/exhaustive-new.json` give **41** before the last inspecting call.

**R2-4. INFO (evidence): reproducer lines are not labelled.**
`evidence/review-reproducers.jsonl` has four mmap lines with no `tree` field. One of them is `before-final` with `attackFired: false` and a genuine result. I believe that line comes from the `d6172ec` run, where the hook's trigger call does not occur, but the file does not say so. On HEAD I confirmed that `before-final` fires and bypasses. Add `tree` and run labels, so that a non-firing line is not read as the patch refusing the attack.

**R2-5. INFO: the copy of my round-1 report has two over-redacted paths.**
In `INDEPENDENT-REVIEW.md`, both `<branch-worktree>` and `<mutation-worktree>` became `<scratch>`. The NOT_RUN line now reads "I read the stored `<scratch>`" where the original named `<evidence-scratch>/fd-mutants.json`. The content is otherwise identical to my report. Cosmetic.

**R2-6. INFO.** `readCheckedFile` is still exported but no longer used by `verifySlot` (only by an older research mutant script). Harmless.

## NOT_RUN in this round
- A new mutation run: in progress elsewhere, so I did not start one.
- The real-race scripts (rename races do not tell the versions apart, see round 1).
- Coarse-timestamp kernels: masked model only.
- tmpfs, overlayfs, NFS; ACLs; non-Linux.
