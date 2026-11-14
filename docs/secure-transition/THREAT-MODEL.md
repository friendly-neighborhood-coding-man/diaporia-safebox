# SSTP V0 threat model (P0)

SafeBox Secure Transition Protocol V0, experiment branch `experiment/secure-transition-v0`, based on the frozen V6 candidate `bf7403d3d85abe43871e9a3b400d86abaeb0edae` (Draft PR #13). Everything runs in a disposable Linux cloud sandbox with MOCK keys and a MOCK ledger. No real funds, no Testnet or Mainnet, nothing on the owner's Windows laptop.

This document was written before the implementation. Where the implementation later changed a decision, the change is marked **[post-impl]**.

## 1. Research question and what "defeated" means

> Can an open-source wallet keep owner control of assets, signing keys, policies and recovery rights when the software publisher or the update distribution infrastructure is malicious?

A publisher signature proves *authorized publication*, never *harmless behaviour*. SSTP therefore does not try to detect malicious code. It tries to make sure that the code being installed never holds the authority it could abuse. The test of success is a capability test, not a code-quality test:

- An attack is **defeated** only if the protected authority (account key, policy, owner and recovery credentials, counters, update trust anchors, witness) is unchanged and no unauthorized ledger effect exists, measured from trusted state outside the attacker's reach.
- If malicious publisher code runs with access to the signing key, the policy database, the trusted updater or the owner environment, the result is **FAIL**, never a qualified PASS.

## 2. Assets

| Asset | Where it lives (Candidate C) | Must never |
|---|---|---|
| Account signing key (MOCK Ed25519; stands for the NEAR access key) | Security Authority private dir, uid `sstp-auth`, mode 0700 | be readable by the app, the updater, the fetcher or a package |
| Policy: Purpose, recipients, per-tx and window limits, approval rules | Authority state | change because the app version changed |
| Owner and recovery credentials, quorum | Authority state (public keys); private keys on the simulated owner device | be replaced by the app or the publisher |
| Counters: consumed authorization nonces, spent budget, security epoch, app version floor, event counters | Authority state, monotonic | decrease, including on application rollback |
| Update trust anchors: pinned TUF root, owner-approved root digests | Controller dir (TUF root), Authority (approved digests) | rotate without owner approval |
| Witness trust anchor | Authority pins the witness public key | be replaced or bypassed |
| Ledger state (balances, nonces, settled tx) | MOCK ledger process, uid `sstp-ledger` | show a transfer the owner policy did not authorize |
| Recovery path: owner FREEZE, recovery-key rotation | Authority | become unavailable during a transition |

## 3. Adversaries

### A. Compromised update server

Controls the HTTP origin the Fetcher downloads from. Can replace, truncate, corrupt or withhold packages and metadata, replay old signed metadata and packages, mix metadata from different versions, delay or interrupt delivery. Holds **no** signing keys.

Invariant A: no package is activated unless its metadata verifies against the locally persisted TUF trust state (signatures, thresholds, versions, expiry, snapshot consistency, hash and length) **and** carries a fresh owner authorization for that exact digest and version.

### B. Compromised publisher (central experiment)

Holds every key a release needs: the TUF root, targets, snapshot and timestamp keys of the publisher. Publishes malicious code that is correctly signed and correctly versioned. Can make the package behave well during checks and badly later (sleeper). Can try to convince the owner to approve an update (it controls release notes, not the owner device).

A valid publisher signature must not, by itself, authorize: reading the owner's protected keys; changing Purpose or limits; changing owner, recovery or quorum; withdrawing assets; replacing the witness or other authorities; disabling verification; rotating the update root.

Invariant B: **even after a correctly signed, owner-approved malicious candidate is activated**, the Authority state and the ledger show no effect beyond what the existing policy already lets *any* application do (spend within Purpose to allow-listed recipients).

What SSTP cannot do against B: stop a malicious app from misusing the capability the policy legitimately gives the app; stop it from lying to the owner in its own UI; stop it from being activated if the owner approves it. These are residuals, not passes.

### C. Compromised running application

The installed application (slot A) is malicious, before or during the update. It runs as uid `sstp-app` with the same capabilities as any app. It may try to: replace the trusted updater; forge transition success; tamper with the inactive slot or the active marker; rewrite version counters or snapshots; request signatures during maintenance; disable isolation; kill or trace other components; use inherited file descriptors, local IPC or privileged helpers.

Invariant C: the controller and witness never trust the application's self-report. Every decision is taken from state the application cannot write: the controller's journal, the slots, the Authority, the witness log, the ledger.

### D. Failures

Process crash (SIGKILL) at every state transition and inside activation; torn journal tail (power-loss model); write errors (EIO, ENOSPC); network interruption during download; concurrent update, FREEZE and recovery requests.

Invariant D: after any failure the system ends in READY (old or new version, consistent), ROLLED_BACK_APPLICATION, REJECTED or SAFE_HOLD. Never: a duplicate ledger effect, a restored nonce, a lower epoch or version floor, a resurrected credential, a settled payment shown as pending, or a lost FREEZE/recovery path.

## 4. Trusted computing base

Trusted (if any of these is malicious, SSTP's claims do not hold):

1. The Linux kernel of the sandbox and its uid, file-permission, process and network-namespace enforcement. In this experiment that kernel is a cloud VM kernel, not a hypervisor we control.
2. The `root` setup harness and the privileged launcher `sstp-run-app` (a fixed script that creates a fresh network namespace, drops to `sstp-app` and executes the slot's entry point).
3. Node.js and OpenSSL (Ed25519, SHA-256) as shipped in the sandbox image.
4. The Security Authority code and its private state (uid `sstp-auth`).
5. The Witness code and key (uid `sstp-witness`).
6. The Transition Controller and Release Metadata Verifier (uid `sstp-ctl`) for **availability and update integrity only**. A compromised controller can activate the wrong code or deny service, but it holds no key that moves funds or changes policy; the Authority must still hold in that case (tested as an extra scenario).
7. `tuf-js` 6.0.2 and `@tufjs/models` 5.0.2 (OpenSSF / sigstore TUF client), pinned by lockfile.
8. The simulated owner device (scripted MOCK approvals in a root-only directory, standing in for an independent hardware device).

Not trusted: the update server, the publisher keys, the package contents, the current and candidate application, the Fetcher, the AI agent, everything reachable on the network.

## 5. Known boundary facts carried over from V6

- In V6 `LOCAL_GATE` mode, any same-user process can sign with the Windows fingerprint-gate key, and the AI side and the approvals run in the same process (`docs/v6/hardening/HARDENING-REPORT.md`, P0.1 `INHERENT_RESIDUAL`). For updates this means the V6 runtime as deployed corresponds to **Baseline A / Candidate B** below: a malicious update of that process holds everything the process holds.
- V6 `HIGH_ASSURANCE` fails closed because no isolated gate exists. SSTP does not change that; it models the separation in a Linux sandbox instead.

## 6. Architectures compared

| | Baseline A | Candidate B | Candidate C |
|---|---|---|---|
| Publisher authentication (TUF) | yes | yes | yes |
| Owner authorization of exact digest | no | yes | yes |
| Inactive-slot install, journal, crash recovery | no (in place) | yes | yes |
| Candidate checked in a fresh network namespace | no | yes | yes |
| Authority and witness in separate uids from app and updater | no (one uid) | no (one uid) | yes |

A and B run the same Authority code; only the deployment changes (all components as one uid `sstp-mono`, keys readable by the app). This keeps the comparison about the boundary, not about code differences. **[post-impl]** see `ARCHITECTURE.md` §4 for the exact uid map.

## 7. Expected security invariants per attack (predictions, written before running)

| ID | A | B | C |
|---|---|---|---|
| U01 unsigned | reject | reject | reject |
| U02 tampered contents | reject | reject | reject |
| U03 old signed version | **accept** (no floor) | reject (floor) | reject (floor) |
| U04 expired or mixed metadata | reject | reject | reject |
| U05 compromised server | reject | reject | reject |
| U06 malicious signed code | **FAIL** (steals) | **FAIL** (steals) | contained; activation possible if owner approves |
| U07 key access | **FAIL** | **FAIL** | blocked by uid |
| U08 Purpose / limits | **FAIL** | **FAIL** | refused by Authority |
| U09 disable verification | **FAIL** | **FAIL** | refused |
| U10 network during isolation | connects | blocked | blocked |
| U11 crash | not recoverable in place | recovers | recovers |
| U12 replay after rollback | **FAIL** if state rolls back with code | holds only if the app does not rewrite state | holds |
| U13 pending/settled across switch | reconcile ambiguity | ok | ok |
| U14 replace updater | **FAIL** | **FAIL** | blocked |
| U15 root rotation | accepted (plain TUF) | refused (owner pin) | refused |
| U16 concurrency | undefined | serialized | serialized; FREEZE always wins |

The experiment's job is to replace these predictions with measurements. Any prediction that turns out wrong is reported, not adjusted.

## 8. What is out of scope and labelled

- TPM, measured boot, remote attestation of the running app, hardware-backed key isolation: **BLOCKED** (no TPM in the cloud sandbox) / **NOT_RUN**.
- Hypervisor-level network isolation: **NOT_RUN**. V0 uses a kernel network namespace created by root, which is host-enforced relative to the app but shares the kernel.
- Updating the trusted updater itself (TCB update): **NOT_RUN**.
- Integration with the actual V6 Vault and Root code: **NOT_RUN**. The SSTP Authority is a model of the V6 Purpose / limits / nonce / FREEZE / recovery semantics with a narrow interface.
- Social engineering of the owner beyond "the owner approves a malicious release": **INHERENT_RESIDUAL**.
