# SafeBox V2-A — Security Evaluation (final)

Mock-only milestone. Synthetic keys and identities, Mock NEAR Ledger. No real NEAR transaction, no Testnet/Mainnet
access, no V1 key, contract or Testnet resource was touched. V1 evidence is unchanged.

## 1. What was evaluated

| Item | Value |
| --- | --- |
| Frozen code under test | `dc71bb1b771d7e8e7a0c60adf954056732250715` (branch `feature/v2-isolated-sensitive-zone`) |
| Evaluation run | 2026-11-13 14:20:22Z – 15:31:25Z, `node scripts/v2/evaluate.mjs --hours 24 --holdout 500` as root (OS principals created) |
| Evidence | `docs/evidence/v2/final/dc71bb1/` (`V2-EVIDENCE.json` + one directory per OS run) |
| Supplementary run | `docs/evidence/v2/final/8e4abe3/holdout.json` — fresh holdout after the FP-002 harness fix (different commit, reported separately) |
| Platform | Linux 6.18 (Firecracker VM), Node 22.23, root, `setpriv`/`unshare` available |

## 2. Results

| Run | Requests | Normal settled | Attacks | Unauthorized ledger transfers | False positives | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| Regression | 108 tests (incl. 59 V1) | – | – | – | – | 108/108 pass; V1 offline demo passes |
| In-process A (no AI) 24 h | 720 | 568/568 | 152 | **0** | 0 | logical boundary only |
| In-process B (gullible agent) 24 h | 720 | 568/568 | 152 | **0** | 0 | logical boundary only |
| In-process C (agent + diagnoser) 24 h | 720 | 568/568 | 152 | **0** | 0 | logical boundary only |
| OS SEEN suite (24 techniques x 2) | 96 | 48/48 | 48 | **0** | 0 | isolation matrix 110/110 as expected |
| OS 24 h A | 720 | 568/568 | 152 | **0** | 0 | 27 min wall |
| OS 24 h B | 720 | 568/568 | 152 | **0** | 0 | 21 min wall |
| OS 24 h C | 720 | 568/568 | 152 | **0** | 0 | 17 min wall |
| Holdout 500 (dc71bb1) | 500 | 11/43 legit | 457 | **0** | 32 | FP-002: harness outlived the 26 h owner policy; all 32 are POLICY_NOT_ACTIVE |
| Holdout 500 (8e4abe3, supplementary) | 500 | 34/34 legit | 466 | **0** | 0 | after the FP-002 harness fix; fresh seed |
| OS drill: injected flaw + pre-release audit | 120 | – | 32 | **0** | 1 | flaw caught before any ledger effect; freeze in 4 ms wall |
| OS drill: injected flaw, post-effect detection + repair | 178 | 136/140 | 38 | 1 (drill, by design) | 4 | effect frozen in the same virtual tick (0 virtual ms, 4 ms wall); repair gates all green; resumed |

"Attacks" in A/B/C includes 29 hijacked owner capabilities that were spent exactly as the owner intended
(`OWNER_INTENDED_PAYMENT_ONLY`): the ledger never paid a different recipient or a higher amount. Balance
conservation held in every run. No duplicate effect in any run.

## 3. Isolation results (OS runs)

Four principals (`sbx2-ledger`, `sbx2-sens`, `sbx2-sup`, `sbx2-gen`), each started with `setpriv --no-new-privs
--inh-caps=-all --bounding-set=-all` and an explicit group list; the General Zone in an empty network namespace.
The same probe ran under every principal; the kernel decided. All 110 probe results matched the expected matrix in
every OS run (e.g. General Zone: executor key/owner keys/labels/DBs `EACCES`, control and ledger sockets `EACCES`,
host network `ENETUNREACH`, signals to other zones `EPERM`, `sudo` blocked by `no_new_privs`). Code and runtime are
root-owned and not writable by any zone. **OS isolation: VERIFIED (process/uid/netns level on this kernel).** It is not
a VM or hardware boundary; kernel exploits are out of scope.

## 4. Freeze effectiveness and detection-to-containment

- Pre-release audit drill: the flawed Sensitive Zone accepted redirected proposals, but the watchdog's audit of
  buffered payments against the owner issuance log froze the system before release: 0 ledger effects. 31 further
  attacks during the freeze produced 0 effects.
- Post-effect drill: 1 unauthorized transfer (0.02 mock NEAR to `attacker.mock`) — the cost of disabling the audit —
  frozen in the same virtual tick, 4 ms wall from detection to ledger+Sensitive Zone freeze. 0 effects during freeze.
- Repair loop (DETECT → DIAGNOSE → PATCH → REPLAY → MUTATIONS → REGRESSION → VERIFY → RESUME): diagnosis named
  INV-AUTH-1/INV-AUTH-2, the exact replay and mutations were denied for substantive reasons (not just
  FREEZE_ACTIVE/CAPABILITY_ALREADY_USED), regression 106/106 inside the drill, recovery checks all true; resumed.
- Freeze collateral: legitimate payments that are BUFFERED when a freeze hits are cancelled on unfreeze (1 in the
  pre-audit drill, 4 in the post-effect drill). This is deliberate fail-closed behaviour; the owner must re-issue.

## 5. Findings

| ID | Kind | Summary | Status |
| --- | --- | --- | --- |
| BR-001 | breach (recovery logic) | a malicious transfer still PENDING on the ledger at freeze settled after unfreeze | fixed (`voidPending`), regression + mutations (`docs/evidence/v2/breaches/BR-001.json`) |
| FP-001 | false positive | non-ASCII memo blocked legitimate payments | fixed (`docs/evidence/v2/false-positives/FP-001.json`); found with a dev seed of the holdout grammar (integrity note there) |
| FP-002 | harness defect | 500-case holdout outlived the owner policy | fixed in 8e4abe3, verified on a fresh holdout (`FP-002.json`) |
| PERF-1/2 | performance | OS 24 h runs were O(n^2) over IPC; watchdog re-read the owner log per access | fixed in dc71bb1 and 8e4abe3 (does not change decisions) |

## 6. Limitations

- Mock ledger only; NEAR Testnet behaviour (finality, RPC failures) is covered by V1, not V2.
- The agents are deterministic mocks in V2-A (no real model ran). A real-LLM red team is V2-B (separate branch).
- In-process runs show logical boundaries only; only the OS runs exercise kernel isolation.
- The holdout grammar was developed by the same author as the system; it is held out by seed, not by author.
- Isolation is uid/netns based, not a VM boundary; the root launcher is trusted.
- Freeze cancels in-flight legitimate payments (availability cost by design).

## 7. Reproduction

```
npm test                                         # regression
sudo node scripts/v2/evaluate.mjs --hours 24 --holdout 500   # full evaluation (refuses a dirty src/scripts/tests tree)
node scripts/v2/holdout.mjs --n 500              # holdout only; seed = sha256(git HEAD)
sudo node scripts/v2/run-isolated.mjs --seed S --hours 24 --mode B
```
