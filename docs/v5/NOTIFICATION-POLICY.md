# Notification policy (Mission 4)

Source: `src/v5/notify/notify.mjs`.

## Separation from authorization

Notifications are **strictly separate from authorization**. Nothing in the notification module can approve, release,
accelerate or authorize anything, and no other module accepts anything from it as an approval. Delivering, opening,
clicking or replying to an e-mail never counts as consent. Messages point the person to their own trusted SafeBox
confirmation path and contain **no approval link**: URLs are stripped from any text derived from the event.

## Recipients

- Only **verified** contacts. Contact digests (`contactRef = SHA-256` of the normalised address) are attested by the
  notification service and pinned in the V5 genesis extension.
- Every key holder of the account is notified for incidents, holds, contests and Rapid-Use events, not only the
  holder of the affected key.
- Addresses live only in the notification service's address book and never in the journal. In experiments they are
  `*@security.example.test`, a reserved test domain.

## Delivery

- Auditable outbox (`outbox.db`): every message has a dedupe key (incident × recipient × kind), so sends are idempotent.
- Retries are bounded (5 attempts; backoff 1 min, 5 min, 15 min, 1 h, 6 h). Delivery status is accounted as
  `DELIVERED`, `TEMPORARY_FAILURE`, `PERMANENT_FAILURE` or `NOT_CONNECTED`.
- Duplicate alerts within 6 h are suppressed; flood control allows 6 per recipient per hour, with the excess summarised.
- A provider outage is retried. A mailbox that rejects is recorded as a permanent failure, and the journal shows it.

## Transports

| Transport | Use |
|---|---|
| `MockTransport` | all tests, scenarios and red-team campaigns (in-process list; nothing leaves the container) |
| `RealProviderAdapter` | reports `NOT_CONNECTED` unless a provider is configured **and** `SAFEBOX_ALLOW_REAL_EMAIL=1`; neither is set anywhere in this work |

**No real e-mail was sent during V5 development or evaluation.** `docs/evidence/v5/email-sandbox.json` holds the MOCK
messages and outbox statistics. The production provider status is `NOT_CONNECTED`.

## Evidence

`tests/v5/notify.test.mjs` (9 tests): only verified recipients, idempotency, outage then retry, permanent failure, flood
control, no approval links, attacker-controlled text sanitised, `NOT_CONNECTED` adapter.
