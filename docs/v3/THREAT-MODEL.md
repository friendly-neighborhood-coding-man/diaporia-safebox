# SafeBox V3 threat model

## 1. Assets and goals

| Asset | Security goal |
|---|---|
| Funds in the vault | Move only under a valid PAYCAP from a live DAILY credential, within the current Purpose and epoch, after the buffer |
| The Purpose (capsule) | Immutable identity fields never change; limits change only by governance quorum (strengthen-only floors) |
| Authority (credentials, matrix, epoch) | Changes only with the matrix quorum or a completed recovery; every change bumps the epoch |
| Owner availability | Losing up to 50% of keys is recoverable without a third party able to veto forever; a full loss is reported truthfully |

**Non-goals.**
- Mainnet operation, real funds, and protecting against a compromised OS kernel or hypervisor.
- Physical coercion of the owner.
- Legal disputes over who the owner is.

## 2. Adversaries

| ID | Adversary | Capabilities |
|---|---|---|
| A1 | **Rogue AI agent** (General Zone) | Every gz port operation; reads public Root state; any prompt-injected goal. No network. No credential |
| A2 | **Thief** | Holds 1–2 owner devices with PIN, so UV succeeds. May hold notification channels |
| A3 | **Colluding guardians / identity verifiers** | Up to all 3 guardians and both identity verifiers |
| A4 | **Insider at a channel provider** | Signs channel ACK/OBJECTION for that channel |
| A5 | **Compromised service** | The recovery service, the vault host, or the Root store (rollback, fork, tamper) |
| A6 | **Network / replay** | Replays any signed object, reorders, duplicates, crashes processes |

## 3. Trust boundaries

1. **Authenticator → Root.**
   - Only signatures count. Each signature is verified against a pinned key and checked for domain, digest, epoch,
     nonce and expiry.
   - WebAuthn must have the UV flag where the matrix requires it, and signCount must increase.
   - The AI cannot produce any of these.
2. **AI (General Zone) → Vault.**
   - Only PROPOSE, STATUS, HEALTH and ROOT_VIEW are reachable.
   - The AI can forward an owner-signed PAYCAP but cannot widen it. Recipient, amount and asset must match exactly.
3. **Root → Vault.**
   - The vault does not trust the Root's *state*. It replays the transitions itself from the pinned genesis.
   - It alarms on a fork, a rollback, or a clock that runs ahead.
4. **Recovery service → Root.**
   - The service can only submit DISPATCH, COMPLETE and RECONSTITUTE.
   - The Root re-checks every completion condition. The notifier key is not a credential.
5. **Contract ↔ account keys (on-chain).**
   - The contract has no privileged method.
   - A FullAccess key on the account would bypass everything, so D1–D4 is a deployment precondition.
6. **OS.**
   - There are five uids. Each zone can read and write only its own state.
   - The pinned keys are readable by all zones and writable by none. There is no cross-zone signalling.
   - The General Zone has no network.

## 4. Threat → control map

| Threat | Control | Evidence |
|---|---|---|
| AI redirects payment / changes amount | Exact recipient, amount and asset in the PAYCAP; vault re-check (V2-B F-B01 kept) | root-lifecycle, V2-B tests, campaigns |
| AI or thief forges "biometric verified" | Canonical encoder rejects booleans; WebAuthn UV flag comes from authenticatorData only | authority-attacks, webauthn |
| WebAuthn replay or clone | Challenge = action digest; nonce single-use; signCount strictly increasing | authority-attacks |
| Stolen single key | Every governance action needs ≥ 2 roles; K4 cannot unfreeze; K3/K5 cannot pay | root-lifecycle, contract tests |
| Stolen key self-revokes or swaps the owner's keys | REVOKE_SELF_APPROVAL; rotation needs SELF plus others; plan keys must be independent | authority-attacks |
| Fake loss claim | Claim changes nothing; all channels notified; any survivor cancels | recovery-attacks |
| Timer-only completion | Every completion requires the full evidence set | recovery-attacks (72 h boundary) |
| Denominator laundering (many small recoveries) | Baseline denominator; recovered keys are provisional for 30 days | recovery-attacks, contract |
| Guardian collusion + 1 stolen key (F-V3-01) | Claimed-lost-key objections are not overridable on reconstitution; survivors must outnumber them; owner channels must ack | F-V3-01 TAP files |
| Stolen channel / one bad guardian vetoes recovery (F-V3-02) | Override on the recovery path with all survivor consents + normal quorum; approvals must outnumber guardian objections | F-V3-02 TAP files |
| Old-epoch authorization reuse | Epoch in every action and PAYCAP; vault cancels stale payments at release | recovery-attacks, contract |
| Root rollback / fork / tamper | Independent replay; hash chain; vault alarm and freeze; Root fails closed on tampered rows | authority-attacks |
| Concurrency, crash, duplicate | Compare-and-append; crash-after-persist replays effects; idempotent denial | authority-attacks |
| Resource exhaustion | Request size and depth caps; case cooldown; pending ≤ 16 | authority-attacks |
| On-chain admin bypass | No privileged method; deployment checker D1–D4 | contract tests, deployment.test |
| Cross-zone OS access | Separate uids, no capabilities, no_new_privs, the General Zone in an empty netns | os-matrix.json |

## 5. Guardian collusion analysis

Default personal profile: 3 guardians, quorum 2 (3 for reconstitution), 2 identity verifiers, 3 channels. The rows
below give the strongest outcome against an owner who holds the remaining keys.

| Colluders + stolen keys | Owner responsive | Owner silent for 72 h |
|---|---|---|
| Guardians only (any number), 0 keys | Nothing. Survivor consent is missing; any survivor cancels | Nothing. They cannot get survivor consents |
| All guardians + both identity verifiers, 0 keys | Nothing | Nothing. With no key, survivor consent is impossible; a 100% "loss" claim is reported RECOVERY_IMPOSSIBLE |
| 1 stolen key + ≤ 2 guardians | Nothing. Owner objects or cancels | Nothing. Reconstitution needs 3 guardians and 2 identity verifiers |
| 1 stolen key + all guardians + both identity verifiers, claiming the other 4 lost | **Nothing.** Owner objections with "lost" keys are not overridable on reconstitution (F-V3-01) and the owner can cancel the lockdown with K3+K2. Funds are frozen during lockdown (DoS, not theft) | **Residual R-1** (below) |
| 1 stolen key + 1 stolen channel + 1 guardian | Before F-V3-02: permanent veto of the owner's recovery. **Now: the owner overrides and recovers** | Nothing (attacker has no path to authority) |
| 3 stolen keys (majority) | Out of scope: the attacker *is* the majority of the owner's authority | Out of scope |

**Residual R-1 (accepted, documented, not fixed).** All of the following are required:
- one stolen key;
- **all three** guardians and **both** identity verifiers colluding;
- **a majority of the owner's own notification channels** compromised, so they can ack NO_OBJECTION;
- the owner silent for the whole 72 h window.

Under those conditions a reconstitution completes and the attacker gets a NEW_EPOCH. The test
`RESIDUAL R-1` in `tests/v3/recovery-attacks.test.mjs` demonstrates it.

Mitigations available to deployers:
- more guardians and a higher reconstitution quorum;
- a longer window;
- out-of-band channels (postal).

The matrix and config floors allow strengthening only.

**Residual R-2 (availability).** On the reconstitution path, a single guardian objection or a single
claimed-lost-key objection blocks completion. This is deliberate: there the survivors are a minority. The case stays
in lockdown and assets are preserved. The owner, holding the lockdown-cancel quorum if any K3+daily survive, can cancel
it.

**Residual R-3 (availability, insider).** A guardian or channel that objects on a minority-loss case where the owner
also lacks the normal guardian quorum (two of three guardians compromised) blocks recovery. The owner still holds a
majority, so governance (revoke a stolen DAILY key and refill the vacancy) remains available for daily keys. A lost
ROOT or RECOVERY key with two of three guardians compromised cannot be refilled.

## 6. Assumptions

- Owner authenticators perform UV honestly. A software authenticator is used in tests.
- Pinned guardian, identity-verifier, registrar and channel keys are distributed out of band at genesis.
- Clocks: the vault uses its own monotonic and virtual clock and alarms if the Root's time runs ahead. On-chain, block
  time is used.
- Recovery-service availability: if it is down, nothing completes. Fail-safe.
- The deployment checker is run before funds are placed in the account. It is not enforced on-chain.
