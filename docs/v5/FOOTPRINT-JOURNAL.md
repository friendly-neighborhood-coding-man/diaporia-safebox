# Footprint Journal (Mission 3)

Source: `src/v5/journal/journal.mjs`. The journal is **tamper-evident, not tamper-proof.**

## Structure

- An append-only SQLite table. Every event is hash-linked to the previous one:
  `hash = SHA-256(domain || canonical(event))`.
- Independently signed checkpoints (every 25 events, journal checkpoint key) are pushed to two witness replicas.
  Deletion, truncation, reordering or modification is **detected** by comparing the chain with the witness checkpoints.
  An administrator can still delete the local file; that is detectable, not preventable.
- Layer-bound writers: `ROOT, VAULT, CONTRACT, NOTIFY, RISK, ANALYSIS, REPORT`. A component receives only its own
  writer and cannot write as another layer. The Analyst's writer can only append findings that reference events.
- Events record: type, layer, time, principal (keyed pseudonym), operation digest, related id, outcome, epoch, Purpose
  version, evidence references, `data`, `untrusted` (attacker-controllable text, ASCII-sanitised) and optional
  `sealed` metadata.

## Privacy

- Forbidden fields are rejected at append time: keys, secrets, PINs, biometrics, raw assertions or signatures, mnemonics
  and tokens.
- Principals are HMAC pseudonyms. Credential ids never appear in the analyst view (F-V5-02 fix: features and assurance
  levels were leaking `k1-phone`).
- Sensitive metadata such as payment memos is sealed with AES-256-GCM under a per-month key. Destroying a period key
  crypto-shreds that period while the hash chain still verifies.
- Role views:
  - `analyst`: pseudonymous, no sealed metadata, untrusted text wrapped as data;
  - `auditor`: adds sealed metadata where the key still exists;
  - `owner`: own account, de-pseudonymised.

## Flood control

Rejected attempts are journaled only after trust-boundary validation, at most 20 per principal per hour. The excess
is counted in one `ATTEMPTS_SUPPRESSED` event, so an attacker cannot hide activity by flooding the journal, and
cannot grow it without bound.

## Retention

The hash chain is kept for the life of the account plus 7 years. Sealed metadata is kept for 400 days, then its key is
destroyed. Analyst findings are kept with the chain and marked INFERRED unless independently corroborated.

## What is journaled

- Root: every accepted transition, and rejected submissions as rate-limited attempts.
- Vault: proposals, rejections, invalid signatures, delays, settlements, cancellations and expiries.
- Risk Policy Engine: its own decisions (`ENGINE_DECISION`).
- Notifications: queued messages and delivery attempts.
- Analyst: findings after review.
- Reports: issued reports.

## Evidence

- `tests/v5/journal.test.mjs` (8 tests): deletion, truncation, reordering and modification are detected; forbidden
  fields are rejected; a layer cannot write as another; shredding keeps the chain verifiable; flood suppression works.
- The verifier checks the chain on every scenario and campaign (`journalOk`).
