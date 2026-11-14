# SSTP V0 architecture: implemented components only

Status: **SSTP V0 PARTIAL EVIDENCE**. This document describes the code that exists at `experiment/secure-transition-v0` (source commit `3e58028`), not the full design in `THREAT-MODEL.md`. Components that the threat model names but that were never written are listed in §4 and are not described as if they exist.

All code lives in `secure-transition/` as a separate package (`package.json`, own lockfile). It does not import or change the V6 payment core. Dependencies, pinned by lockfile: `tuf-js` 6.0.2, `@tufjs/models` 5.0.2 and `@tufjs/canonical-json` 2.0.0. Cryptography is Ed25519 and SHA-256 from Node's OpenSSL binding. No custom signature scheme.

## 1. Separation actually present

Every component below is a module. **All tests run them in one Node process as one OS user (root) in a disposable cloud container.** The only separation demonstrated is logical: different modules, different interfaces, different signing domains. No uid, filesystem-permission, process or network boundary has been demonstrated. The Authority and witness daemons and the socket transport exist as code but were never started.

## 2. Components

| Component | Files | What it does | Trust role |
|---|---|---|---|
| Strict package reader | `src/package/tar.mjs` | Bounded ustar parser. Accepts only regular files (mode 0644/0755) and directories (0755). Rejects symlinks, hardlinks, devices, FIFOs, pax/GNU extension headers, absolute paths, `..`, `.`, empty segments, backslashes, hidden or odd names, case-insensitive duplicates, a file used as a directory prefix, bad checksums, truncation and trailing data. Limits: 8 MiB archive, 256 entries, 4 MiB per file, 16 MiB total, depth 8, path 200. Also has a permissive writer, used only to build test fixtures. | Untrusted input parser |
| Canonical manifest | `src/package/manifest.mjs` | The first entry must be `SSTP-MANIFEST.json`, byte-identical to its canonical JSON. Exactly six fields (`format, name, version, entry, authoritySchema, files`); unknown fields such as hooks or policy are rejected. Every other file is listed exactly once with SHA-256, size and mode; entry `main.mjs` is required. | Package integrity |
| Slot installer | `src/package/install.mjs` | Installs into an allow-listed, canonical, non-symlink directory. Checks free space (2× package size), wipes the slot, creates files with `O_CREAT\|O_EXCL\|O_NOFOLLOW`, fsyncs, then re-reads and re-hashes everything (`verifySlot`: exact file set, digests, modes, no symlinks, not group/other-writable, optional owner uid). | Install integrity (not activation) |
| Release Metadata Verifier | `src/verifier/tuf.mjs` | Runs the `tuf-js` client offline against a spool directory, with a locally persisted trust directory (`root.json` pinned out of band). SSTP additions: (1) a root gate: any new `N.root.json` must have a SHA-256 in an owner-approved list, or `ROOT_ROTATION_NOT_OWNER_APPROVED`; passing `null` gives plain TUF, which is Baseline A; (2) the target must carry `custom.sstp.version`. Expiry is checked against the real clock, with no offline exemption. Errors are mapped to codes (`TUF_EXPIRED`, `TUF_ROLLBACK`, `TUF_ROLLBACK_OR_MIX`, `TUF_BAD_SIGNATURE`, `TUF_HASH_MISMATCH`, `TUF_LENGTH_MISMATCH`, `TARGET_NOT_LISTED`, …). Never executes package code. | Publisher authentication, release authorization |
| Update Fetcher | `src/fetcher/fetcher.mjs` | Mirrors `N.root.json`, `timestamp.json`, `snapshot.json`, `targets.json` and one target from an HTTP origin into a spool, with size caps and timeouts. Verifies nothing, holds no keys. | Untrusted |
| Publisher repository builder | `src/publisher/repo.mjs` | Builds and signs TUF repositories through `@tufjs/models`: thresholds, multiple keys per role, `consistent_snapshot: false`, expiries, root rotation cross-signed by old and new root keys. Exposes raw file overwrite for compromised-server tests. Test fixture only. | Test fixture (models publisher and server) |
| Security Authority (logic) | `src/authority/authority.mjs` | A model of the V6 Purpose / limits / nonce / FREEZE / recovery semantics. **It is not the V6 Root or Vault code.** See §3. | Owner authorization, policy enforcement |
| Security Authority (daemon) | `src/authority/daemon.mjs` | Unix-socket front end with an app table and a controller table. | **IMPLEMENTED_UNTESTED** |
| MOCK ledger | `src/ledger/ledger.mjs` | Balances, per-account nonces, signature check, mempool, deterministic `tick()` settlement, tx status and history. Settles independently of SafeBox state. The class is tested; its TCP/admin daemon is not. | Authoritative settlement (MOCK) |
| Witness | `src/witness/witness.mjs`, `daemon.mjs` | Baseline of Authority counters; candidate and READY attestations from state it reads itself. | **IMPLEMENTED_UNTESTED** |
| Journal | `src/common/journal.mjs` | Append-only, hash-chained, fsync'd. A torn last line is dropped; a break earlier in the file is reported as tampering, and appends then refuse. The chain detects corruption, not a writer who can rewrite the file. | Crash-consistency primitive |
| Helpers | `src/common/{crypto,fsutil,ipc,faults}.mjs`, `src/deploy/owner.mjs` | Domain-separated Ed25519 envelopes over canonical JSON; durable write via temp + fsync + rename + dir fsync; JSON-lines IPC (untested); fault-injection hooks (never triggered by a test); simulated owner device with owner and recovery keys (scripted MOCK approvals). | — |

## 3. Security Authority rules (as implemented and unit-tested)

State: account key (file), owner and recovery public keys, revoked owner keys, Purpose `{id, version, recipients, perTxMax, budget}`, spent budget, next ledger nonce, payment records keyed by requestId, consumed owner-command nonces, epoch, schema, frozen, maintenance, safe hold, active release, version floor, pending owner-authorized update, owner-approved TUF root digests, witness public key, refusal log.

- **Payments.** Inside Purpose (allow-listed recipient, ≤ perTxMax, cumulative spent ≤ budget) the Authority signs without the owner. This is the capability any application version legitimately has. Outside Purpose it needs an owner `APPROVE_PAYMENT` bound to `{requestId, to, amount}`, the current epoch, an unexpired time and an unused nonce. Refused while frozen, in safe hold or in maintenance. requestId is idempotent: the same request returns the same txid; a different amount or recipient gives `REQUEST_ID_REUSED`. The reservation (spent, nonce, signed tx) is persisted before broadcast. Budget is never restored.
- **Governance.** No policy setter exists for applications. Owner commands: `AUTHORIZE_UPDATE` (owner; version must exceed the floor), `APPROVE_UPDATE_ROOT` and `SET_WITNESS` (owner + recovery), `POLICY_MIGRATION` (owner for strictly tighter Purpose, owner + recovery for anything more permissive or for a schema change; bound to the current policy digest), `FREEZE` (owner or recovery), `UNFREEZE` and `END_SAFE_HOLD` (owner + recovery), `ROTATE_OWNER` (recovery; revokes old owner keys and bumps the epoch).
- **Maintenance protocol.** `beginMaintenance` (one transition at a time), `reconcile` (queries the ledger; marks settled and failed; rebroadcasts the same signed tx if the ledger has never seen it; if the ledger shows any tx from the account that the Authority did not sign, or a higher account nonce, it freezes and enters safe hold with `KEY_COMPROMISE_SUSPECTED`), `completeTransition` (needs reconciliation plus a witness `READY` attestation bound to the transition id, the current policy digest and epoch, and the owner-authorized release; raises the version floor).

## 4. Named in the threat model, not implemented

| Component | Status |
|---|---|
| Trusted Transition Controller (state machine `IDLE → … → READY`, terminal and recovery states, lock, recovery from journal) | **NOT_IMPLEMENTED** |
| A/B active marker and activation / rollback procedure | **NOT_IMPLEMENTED** |
| Privileged launcher, separate OS users, network-namespace isolation | **NOT_IMPLEMENTED** (stopped by the operator after two safety interruptions; see `PARTIAL-RESULTS.md` §5) |
| Reference application and candidate health check | **NOT_IMPLEMENTED** |
| Baseline A / Candidate B / Candidate C deployments and campaign harness | **NOT_IMPLEMENTED** |
| Mutation-testing script, demo script, clean-room script (named in `package.json` scripts but absent) | **NOT_IMPLEMENTED** |
| TPM, measured launch, hardware-backed keys | **BLOCKED** (no TPM device in the cloud container) |
