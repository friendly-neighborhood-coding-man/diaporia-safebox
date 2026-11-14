# SafeBox parallel falsification sprint — operator review summary

**Status:** `READY_FOR_OPERATOR_PARALLEL_VALIDATION_REVIEW` (research-only; operator-provided sprint report). **NOT integrated, released, merged or deployed.** Three prototype branches were saved as local bundles, not pushed. Frozen V6 `a8ce018`, payment code, submission video and ledger remain unchanged.

Baselines: SSTP PR #34 `92b27d2`; legacy PR #32 `9a38298`; isolation design PR #33 `5f749ff`. Host reported as Linux 6.18.44, Node 22.23.4; tested ext4 (nanosecond and one-second timestamps), tmpfs and overlay. fs-verity was **NOT_RUN** (kernel lacks support). Track D was **BLOCKED_BY_SAFETY_GATE / NOT_RUN** on operator decision, not a passing security test.

## Evidence-based findings

| Area | Observed outcome | Verdict |
|---|---|---|
| A / Verified bytes | The previous verify-then-open consumer received foreign bytes under retained writable mappings, mmap writes and after-return rewrite. Snapshots of the hashed buffer delivered genuine bytes or refused in scoped tests. **But** an attacker of the same uid could modify a memfd **before sealing**; the reviewer reproduced foreign bytes after SUCCESS. Seal-first, re-hash-after-seal rejected that attack in a reviewer experiment. | **PARTIAL; proposed combined pipeline not implemented** |
| B / Owner log | Inode reuse defeated owner-log `dev:ino` identity (10/10 on relevant ext4/overlay trials); held descriptors alone, prefix hashes and unsigned chains did not authenticate record authority. Owner-signed hash chain + signed head + independent anchor yielded **0 unauthorized POLICY across the tested T1/T2 cells**, but putting the anchor/owner keys in the same writable `sup/` directory allowed a forged POLICY at restart. Writer-with-key remains out of scope. | **VERIFIED_SCOPED only when anchor is independent; deployment NOT_RUN** |
| C / Races and resource limits | Held descriptors blocked inode-reuse N1 (0/8 bypass in test). Strictly bounded reads stopped N3's sparse-growth resource consumption. `verifySlotBytes` returned genuine bytes in 1,886/1,886 accepted schedules (digest-check mutant returned foreign in 850). **Still:** after-check mmap writes can bypass path verification; coarse timestamps broaden closing windows, EMFILE errors are unnormalized and a 256-file deep tree needs ~2,050 FDs. | **VERIFIED_SCOPED for returned bytes/N1/N3; PARTIAL overall** |
| D / Signed-launcher deputy | Stopped before any exercise by a safety gate, and not retried. The potential signed-malicious-package and delayed/withheld FREEZE risks remain unassessed. | **NOT_RUN; no containment claim** |

## Proposed next design (not integrated)

1. **Consume only authenticated bytes.** One manifest-bounded read (research cap: 16 MiB total), with source descriptors held for relevant checks. Copy to a memfd, **seal before the final digest verification**, verify seals and digests again, then give only that sealed fd to a consumer launched by **absolute trusted path**. The consumer must reject arbitrary writable/non-memfd descriptors and check the expected digest/seals itself. Do not reopen the original slot path. This combined implementation and full activation path are **NOT_IMPLEMENTED**.
2. **Keep authority outside the log writer.** Owner signs policy statements independently; a signed head and trust anchor must be outside `sup/` and inaccessible for modification or signing by the app/log writer. Define staleness bounds, signed re-anchoring and safe recovery after rotations; preserve auditable, monotonic state.
3. **Build OS-enforced trust boundaries before release claims.** Authority, Witness, controller and app need distinct principals and verified provenance, a trusted launcher with no inherited FDs, network isolation, and an **independent owner FREEZE channel** not relayed by the app. The B1–B6 separation is **NOT_IMPLEMENTED / NOT_RUN**. A correctly signed malicious app package is **not contained** by submitted V6.
4. **Reproduce on supported target platforms**, including fs-verity when available and full end-to-end consumer launch; validate failures, availability and resource ceilings. `installToSlot` still lacks `expectUid`.

## Claims explicitly falsified

- File inode identity or a held FD alone establishes content or log integrity.
- Prefix hash or file permissions prove that a writer cannot change the bytes.
- A memfd is safe irrespective of the interval **before** it is sealed.
- Path verification plus closing checks is independent of timestamp granularity.
- The preexisting `RLIMIT_NOFILE` expectation is sufficient for deeply nested trees.

**Scope warning:** Results are from operator-supplied MOCK-based prototype and independent-review reports, not a real-funds deployment. Passing an integrity test does **not** prevent a correctly signed malicious app from executing with the permissions its process holds. Nothing here is evidence of production immutability or hardware-isolated signing.

References: [SSTP PR #34](https://github.com/friendly-neighborhood-coding-man/diaporia-safebox/pull/34) · [Legacy PR #32](https://github.com/friendly-neighborhood-coding-man/diaporia-safebox/pull/32) · [Isolation design PR #33](https://github.com/friendly-neighborhood-coding-man/diaporia-safebox/pull/33). Full raw evidence and git bundles remain with the operator; this note is a summary of their supplied report, not a public mirror of those files.
