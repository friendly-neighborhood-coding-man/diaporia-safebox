# SSTP isolation research: what PR #16 leaves unenforced, and what a defence would need

Status: **RESEARCH ONLY. Nothing here is implemented or run.** Base: PR #16 (`experiment/secure-transition-v0`, head
`c256ffa`, tested code `3e58028`). MOCK only. No launcher, controller, OS-user or network-namespace code was written for
this document. The operator's 15:50Z instruction (no further controller or launcher attempt after two safety
interruptions, `PARTIAL-RESULTS.md` §5) stands; any build-out below needs a fresh explicit go from the operator.

**No malicious-code containment is claimed.** A containment claim needs OS-isolated adversarial execution evidence
(§6). None exists for SSTP. The only OS-level evidence anywhere in the SSTP work is the slot-permission probe on the
separate Mission 1 branch (`security-fix/sstp-fd-verifier`, `tests/os/verifyslot-uid.spec.mjs`): a second uid cannot
rename or rewrite a root-owned slot. That is a statement about Linux file permissions for one directory, not about a
separated SSTP deployment.

## 1. Question

Can SSTP keep the **Owner authority, account signing keys, the Purpose policy ("Purpose Root"), protected Vault /
Authority state and the recovery controls** intact when (A) the update server is compromised, or (B) the publisher is
compromised and ships a correctly signed, correctly versioned malicious package?

Short answer from what exists today:

- **A (compromised server):** mostly defended at the verifier layer (TUF + owner root gate), VERIFIED_VERIFIER_LAYER.
  Four gaps remain (§3), all fixable without OS isolation except the slot write path.
- **B (malicious signed package):** **not defended.** A verifier cannot tell harmful from harmless signed code. The only
  defence is that the activated code never holds the authority it could abuse. That is an OS-boundary property, and
  every boundary that would provide it is NOT_IMPLEMENTED (§2). In the current deployment shape (one OS user, as in the
  tests) a malicious package holds everything the process holds: SSTP today is **Baseline A/B**, not Candidate C.

## 2. Unimplemented boundaries in PR #16, by asset

| # | Boundary (THREAT-MODEL §4/§6) | Protects | Against | PR #16 status | Minimum requirement | Evidence that would show it |
|---|---|---|---|---|---|---|
| B1 | Separate uid for the Security Authority (`sstp-auth`), private dir 0700 | account key, Purpose, owner/recovery keys, counters, approved root digests | B, C | NOT_IMPLEMENTED (everything runs as root) | Authority runs as its own uid; key and state files owned by it, 0600 in a 0700 dir; no other uid in its group; started by a root launcher that is not app-writable | non-destructive access probes from the app uid: `open(key, O_RDONLY)` and `open(state, O_WRONLY)` give EACCES; Authority state hash unchanged; ledger shows no unsigned tx |
| B2 | App-facing Authority socket limited to the app method table | Purpose Root, governance | B, C | daemon IMPLEMENTED_UNTESTED; app socket is created 0666 (any local uid can call `pay` within Purpose and relay signed owner commands) | the app table stays minimal (`status`, `pay`, `ownerCommand`); controller socket 0660 to a group only the controller is in; Authority checks every argument (already true in-process) | benign request clients (per the 15:19Z rule) calling every method from the app uid; controller methods return `METHOD_NOT_ALLOWED` or EACCES on connect; Authority state unchanged |
| B3 | Separate uid for the Witness (`sstp-witness`) and its key | witness trust anchor, transition attestations | B, C | NOT_IMPLEMENTED; Witness class IMPLEMENTED_UNTESTED | witness key 0600 in the witness uid's dir; witness reads slots, marker and staged archives read-only | witness key unreadable from app and controller uids; a forged READY attestation is refused by `completeTransition` |
| B4 | Slot directories, active marker and staged archives writable only by the controller (`sstp-ctl`) | install integrity, what gets activated | B (running app), C | NOT_IMPLEMENTED | slots, marker and staging owned by the controller uid, no group/other write, every ancestor protected (sticky ancestors allowed); verifier called with `expectUid = ctlUid` | Mission 1 branch: `assertProtectedPath` + `tests/os` show the permission half for one slot (VERIFIED for that probe only). Still needed: the same under a real controller uid with the app running |
| B5 | Privileged launcher `sstp-run-app` (drops to `sstp-app`, fresh network namespace, no inherited fds, no ambient capabilities) | everything above | B | NOT_IMPLEMENTED (operator stop) | fixed root-owned launcher; `setgroups`/`setgid`/`setuid` to `sstp-app`, `no_new_privs`, close-on-exec for all fds, empty env, new netns with no route except an allow-listed Authority socket | process table and `/proc/<pid>/status` of the launched app: uid/gid, CapEff 0, NoNewPrivs 1, open fds; `connect()` to the ledger/Internet fails; Authority still the only signer |
| B6 | Network namespace during candidate checks | ledger, owner channel | B | NOT_IMPLEMENTED | candidate health check runs with no network except the Authority app socket | `connect` attempts from the candidate fail (EACCES/ENETUNREACH) and the ledger shows nothing |
| B7 | Transition controller state machine + journal permissions | availability, rollback without financial rollback | A, B, D | NOT_IMPLEMENTED; journal is a hash chain without file protection | controller journal owned by `sstp-ctl` 0600; Authority counters authoritative for money (already true in-process) | crash-at-every-state campaign; counters never decrease; no duplicate ledger effect |
| B8 | Authority → verifier flow of approved root digests and version floor | update trust anchors | A, B | NOT_IMPLEMENTED (tests pass the digest list by hand) | the controller obtains approved digests and the floor from the Authority over the controller socket at verification time; the verifier refuses when it cannot reach the Authority | test where a compromised controller passes a forged list: Authority refuses `completeTransition` for an unapproved root/digest |
| B9 | Hardware-backed keys / measured launch | account key at rest, launcher integrity | B with root, kernel compromise | BLOCKED (no TPM in the container) | out of scope for V0 | — |

## 3. Adversary A: compromised update server

What holds today (VERIFIED_VERIFIER_LAYER, tests 19–30): unsigned, under-threshold, tampered, rolled-back, expired,
mixed and withheld metadata are refused; a cross-signed root rotation needs an owner + recovery approved digest.

Gaps:

1. **B8**: approved root digests and the version floor are passed to the verifier by the test, not fetched from the
   Authority. A compromised controller (or a test bug) could pass a permissive list. Requirement: fetch from the
   Authority, fail closed if unavailable.
2. **Spool and staging are writable by whoever runs the fetcher** (one uid today). The Witness re-hashes the staged
   archive against the owner-authorized digest, which detects substitution, but only if the Witness and the archive are
   outside the attacker's write access (B3, B4).
3. **Slot write path.** PR #27 left directory swap-and-swap-back open during the walk (PR #31). The Mission 1 branch
   closes every in-walk race in the deterministic model. **Verify-then-use after `verifySlot` returns stays open** while
   the attacker can write the slot. A server-only attacker cannot write the slot, so for adversary A alone this is not
   reachable; it becomes reachable as soon as the running app (C) or a malicious candidate (B) shares the uid.
4. **Freeze attacks / indefinite withholding**: timestamp expiry makes stale metadata fail closed (test 27). Delivery
   timing, interrupted downloads: NOT_RUN.

Smallest defensible fix set for A: B8 (code, no OS work), plus B4 for the slots (permissions only), plus keeping the
Mission 1 verifier. None of these is containment of malicious code.

## 4. Adversary B: correctly signed malicious package

A publisher signature proves authorized publication, not harmless behaviour (THREAT-MODEL §1). After owner approval and
activation, malicious code runs as the application. SSTP's design answer is capability separation:

| Asset | What the malicious app must not be able to do | Boundary that enforces it | Status |
|---|---|---|---|
| Owner authority (owner/recovery keys, quorum) | replace owner keys, approve its own commands | owner keys live on the owner device; Authority accepts only signed owner commands; B1/B2 | in-process VERIFIED; OS NOT_RUN |
| Account signing key | read or use the key directly | B1 (key unreadable by app uid), B5 | NOT_RUN |
| Purpose Root (recipients, limits, budget) | widen Purpose | no app-callable policy setter (VERIFIED_IN_PROCESS); B1 so state cannot be rewritten on disk | in-process only |
| Protected Vault / Authority state (counters, payments, nonces, epoch, floor) | roll back counters with the code | B1; Witness monotonic checks (IMPLEMENTED_UNTESTED) | NOT_RUN |
| Recovery controls (FREEZE, recovery rotation) | block FREEZE, delay owner commands | FREEZE accepted during maintenance (in-process); but the app socket relays owner commands, so an app can **withhold or delay** them (PARTIAL-RESULTS §4 item 5) | RESIDUAL: needs an owner channel that does not pass through the app |
| Update trust anchors | rotate the TUF root, lower the floor | owner + recovery quorum (VERIFIED_IN_PROCESS); B8 | partial |
| Slots / marker / witness | swap code after the Witness checked it; forge READY | B3, B4, Mission 1 verifier | NOT_RUN |

Inherent residuals even with every boundary in place (INHERENT_RESIDUAL, not passes):

- In-Purpose spending: any app version, malicious or not, can spend within Purpose to allow-listed recipients without
  the owner. Mitigation options (research questions, not implemented): reset or tighten the budget across a version
  change; require an owner re-confirmation of Purpose after activation; a cool-down window after activation.
- The app controls its own UI and can lie to the owner. The owner device must show the authoritative facts
  (recipient, amount, digest, version) itself.
- Owner approval of a malicious release cannot be prevented, only made informed.
- Sleeper behaviour: health checks before activation cannot detect it.

## 5. Relation to V6

SSTP's Authority is a model of the V6 Purpose / limits / nonce / FREEZE / recovery semantics; integration with the V6
Vault and Root code is NOT_RUN. In V6 `LOCAL_GATE` any same-user process can sign with the gate key (P0.1
INHERENT_RESIDUAL), and the AI side and approvals share one process. So **the V6 runtime as deployed corresponds to
Baseline A / Candidate B**: a malicious update of that process holds everything the process holds. Nothing in SSTP
changes the V6 submission candidate `a8ce018`.

## 6. Evidence a containment claim would need (none of it exists)

1. A real multi-uid deployment (B1–B5) started by a root launcher, in a disposable VM or a separately administered host
   rather than in the same container as the test harness.
2. Per the operator's 15:19Z scope rule: **benign, deterministic request clients only** (no executable malicious
   payloads), acting as the candidate app through the normal interfaces: a policy-change request, a protected signing
   request outside Purpose, a key-file open, a write to the slot/marker/witness/journal, a connect to the ledger. Each
   must be refused by an OS boundary or by the Authority; a refusal by an app-side check does not count.
3. Equivalent initial state across Baseline A, Candidate B and Candidate C, so the difference is the boundary.
4. Measured from trusted state outside the app's reach: Authority state hash, ledger history, witness log, file
   permissions; each probe's errno recorded.
5. Every untestable case reported NOT_RUN; every falsified THREAT-MODEL §7 prediction reported as such.
6. A P2 pass would still mean interface-level capability enforcement only: not resistance to native code, kernel or
   launcher compromise, or hardware attacks.

## 7. Recommended order (each step needs the operator's go where marked)

1. B8 (Authority-sourced digests and floor): code only, in-process tests. No OS work.
2. Mission 1 verifier + `assertProtectedPath` adopted by the Witness (`expectUid = ctlUid`) — on its branch, after
   review.
3. Decide **where** isolation runs (operator decision): a disposable VM with a fixed root setup script is preferable to
   building the launcher inside the test container, and keeps the harness outside the attacker's uid.
4. Only then B1–B6 and the §6 campaign (**operator go required**; the 15:50Z stop applies until then).
5. Owner channel that does not pass through the app (FREEZE/recovery residual).

## 8. Labels used

FIXED (code + tests on a branch), PARTIAL, VERIFIED_IN_PROCESS, VERIFIED_VERIFIER_LAYER, IMPLEMENTED_UNTESTED,
NOT_IMPLEMENTED, NOT_RUN, BLOCKED, RESIDUAL / INHERENT_RESIDUAL, as defined in `EVIDENCE-MATRIX.md`.
