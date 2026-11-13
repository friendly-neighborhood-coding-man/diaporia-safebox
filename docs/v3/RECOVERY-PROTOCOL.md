# SafeBox V3 Recovery Protocol V0

Implementation: `src/v3/root/chain.mjs` (`RECOVERY_*`, `RECONSTITUTE`), `src/v3/recovery/service.mjs` (notifier), and the
on-chain counterpart in `contract-v3/src/lib.rs`. Owner-side procedure: `src/v3/recovery/sim.mjs`.

## 1. Principles

1. **A claim is not authority.** Opening a case changes no credential, no epoch and no purpose. An allegedly lost key
   keeps working until completion, unless the owner suspends it.
2. **Everyone is told.** The recovery service notifies **every** registered channel (phone, e-mail, postal) with the
   case digest. Its notifier key is not a credential.
3. **The timer never approves.** Expiry of the objection window is necessary but never sufficient. All evidence must
   be present when the window ends.
4. **Assets are preserved.** No recovery path moves funds. Lockdown blocks payment and amendment. Old epochs die.
5. **Report the truth.** If nothing survives, the result is `RECOVERY_IMPOSSIBLE`, with no fake success.

## 2. States

```
NORMAL ──open──► LOSS_REPORTED ──dispatch (all channels)──► IDENTITY_CHECK
IDENTITY_CHECK ──identity verified──►
    ≤ 50 % of baseline lost  → RECOVERY_CHALLENGE ──all evidence + window──► RECOVERED  (epoch+1)
    > 50 % lost              → EMERGENCY_LOCKDOWN → RECONSTITUTION ──stricter evidence + window──► NEW_EPOCH (all old keys retired)
    100 % lost               → RECOVERY_IMPOSSIBLE (reported, assets stay locked)
any state ──objection──► HOLD   (DISPUTED)
HOLD ──withdraw / override (§5)──► previous state
LOSS_REPORTED..RECONSTITUTION ──cancel by a survivor (or the lockdown quorum)──► CANCELLED
```

## 3. Evidence

| Evidence | Signed by | Bound to |
|---|---|---|
| `RECOVERY_DISPATCH` | recovery notifier key | case digest, the full channel list |
| `RECOVERY_IDENTITY` | pinned identity verifier (`idv-1`, `idv-2`) | case digest, subject holder, method |
| `RECOVERY_OFFICIAL` | pinned registrar | document type/ref (death certificate, court order) |
| `RECOVERY_CONSENT` | each **surviving** credential | case digest |
| `RECOVERY_GUARDIAN` APPROVE / OBJECT / WITHDRAW | pinned guardian key | action digest + decision |
| `RECOVERY_ACK` NO_OBJECTION / OBJECTION | pinned channel key | case digest |
| `RECOVERY_OBJECT` / `RECOVERY_WITHDRAW` | any live credential (including allegedly lost ones) | case digest |

The **case digest** commits to the case ID, kind, lost set, plan (new credentials with enrollment proofs), subject
holder, open time and nonce. Evidence for one case cannot be used for another. Evidence prepared in one epoch is dead
in the next.

## 4. Completion rules (default config)

| Parameter | Value |
|---|---|
| objection window `windowMs` | 72 h |
| early completion floor `minWindowMs` | 1 h, and only if **every** channel acked NO_OBJECTION |
| guardian quorum (recovery) | 2 of 3, counted by distinct guardian holders |
| guardian quorum (reconstitution) | 3 of 3 |
| identity attestations (reconstitution) | 2 distinct verifiers |
| case cooldown | 1 h between cases |
| provisional period for new keys | 30 days (cannot consent to further recoveries) |
| reconstitution cooldown | 30 days |

**Minority loss, ≤ 50% of the baseline (→ RECOVERED).** Completion needs all of the following:
- identity verified;
- consent from **every** surviving credential;
- guardian quorum;
- no open dispute;
- window elapsed (or the 1 h floor with all channels acked);
- plan roles exactly replace the lost roles.

The lost keys are revoked, the plan keys are installed as provisional, and the epoch is incremented.

**Majority loss, > 50% (→ NEW_EPOCH).** Confirming identity triggers **emergency lockdown**. Completion then needs:
- 2 identity attestations;
- the reconstitution guardian quorum (3);
- consent from **every** surviving credential, with at least `reconMinSurvivors` (1) surviving;
- a NO_OBJECTION ack from **a majority of the subject holder's channels**;
- the full 72 h window, with no early completion;
- a plan that covers the full role set (otherwise the case stays in lockdown until a guardian-approved `RECOVERY_REPLAN`, which resets the window and all evidence).

All old credentials are retired and the baseline is replaced.

**Everything lost.** The result is `RECOVERY_IMPOSSIBLE`, and that is what gets reported. The owner's remaining paths
are off-system: the account's legal and estate process. The assets stay locked, not moved.

**Denominator.** The denominator is the **baseline** credential set fixed at genesis or at the last ratification.
Keys recovered since the baseline still count as lost. So a series of minority recoveries cannot launder a majority
replacement past the reconstitution rules. This is tested in JS and on-chain.

**Deceased or missing holder (multi-administrator).** This path requires all of:
- a registrar-signed official document (`RECOVERY_OFFICIAL`);
- identity verification of the successor;
- guardians;
- the window.

A police report, a news article, or an AI-produced statement grants nothing.

## 5. Objections and overrides

| Objection by | Recovery path (≤ 50%) | Reconstitution path (> 50%) |
|---|---|---|
| a surviving credential | must be withdrawn; never overridable | must be withdrawn; never overridable |
| a claimed-lost credential ("subject") | overridable if all survivors consented + guardian quorum + identity, and survivors **strictly outnumber** the objecting lost keys (F-V3-01) | **not overridable** (F-V3-01) |
| a notification channel | overridable with all survivor consents + guardian quorum (2) + identity (F-V3-02) | overridable with all survivor consents + reconstitution guardian quorum (3) + identity |
| a guardian | overridable only if guardian approvals (excluding objectors) reach the quorum and **strictly outnumber** guardian objections (F-V3-02) | **not overridable** |

Why these rules hold up:
- On the recovery path, *every* surviving credential must consent, and the survivors are a majority of the baseline.
  That is the strongest evidence of ownership in the system. One channel, one stolen lost key, or a minority of
  guardians must not be able to veto it forever. That veto was F-V3-02, found by red-team campaign A.
- On the reconstitution path, the survivors are a minority. A colluding guardian and identity quorum plus one stolen
  key could otherwise claim the real owner's keys "lost" and override the owner's objections. That was F-V3-01.

## 6. While a case is open

- One case at a time, with a 1 h cooldown between cases.
- Purpose amendment, matrix amendment, rotation, revocation and vacancy replacement are refused (`noCase`).
- Freeze (K4) always works. Payments continue unless lockdown is active.
- A survivor can cancel a false claim with a single signature. During lockdown, cancelling needs the
  `LOCKDOWN_CANCEL` quorum (ROOT + DAILY).

## 7. Measured utility (32-case loss sweep, `docs/evidence/v3/recovery-combinations.json`)

| Keys lost (of 5) | Cases | Outcome | Latency | Owner actions | Payment works afterwards |
|---|---|---|---|---|---|
| 0 | 1 | no recovery needed | n/a | 0 | n/a |
| 1 | 5 | RECOVERED | 1.02 h (all channels acked) | 11 | 5/5 |
| 2 | 10 | RECOVERED | 1.02 h | 10 | 10/10 |
| 3 | 10 | NEW_EPOCH | 72.02 h | 11 | 10/10 |
| 4 | 5 | NEW_EPOCH | 72.02 h | 10 | 5/5 |
| 5 | 1 | RECOVERY_IMPOSSIBLE (reported) | n/a | 2 | n/a |

"Owner actions" counts the signed submissions the owner's side makes: open, identity, consents, guardians and channel
acks.
