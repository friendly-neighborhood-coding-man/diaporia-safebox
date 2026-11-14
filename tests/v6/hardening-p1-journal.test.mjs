// V6 hardening P1.7 (issue #14): journal tail truncation.
// Attacker capability: write access to the journal's local SQLite file (an infrastructure administrator or malware on
// the Vault host): can drop the append-only triggers and delete the newest events. Cannot rewrite the external witness
// replicas (they only accept correctly signed, monotonically extending checkpoints) and does not hold the checkpoint key.
// Invariant: deleting any security-critical event (owner payment approval, freeze, hold, revocation, incident ...) is
// DETECTED by the independent verifier. Bound: only non-critical events written after the newest checkpoint can vanish
// undetected (at most checkpointEvery - 1 of them).
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildV6, ok, Y } from './helpers6.mjs';
import { verifyWorld6 } from '../../src/v6/supervisor/verifier.mjs';
import * as J from '../../src/v5/journal/journal.mjs';
const CHECKPOINT_NOW_TYPES = J.CHECKPOINT_NOW_TYPES ?? new Set();

/** Attacker: drop the append-only trigger and delete every event from `fromSeq` on. */
function truncateFrom(w, fromSeq) {
  const db = w.journal.db;
  db.exec('DROP TRIGGER IF EXISTS ev_no_delete');
  db.prepare('DELETE FROM events WHERE seq >= ?').run(fromSeq);
}
const lastOf = (w, type) => w.journal.rows().map((r) => JSON.parse(r.body)).filter((e) => e.type === type).at(-1);

for (const [name, act, type] of [
  ['an owner payment approval', async (w) => ok(await w.pay({ credId: 'k1-phone', amountYocto: Y(1) })), 'OWNER_PAYMENT_APPROVAL_VERIFIED'],
  ['an owner FREEZE', async (w) => ok(await w.cmd('FREEZE', { freezeId: 'f-trunc', reason: 'owner freeze', source: 'owner' }, ['k1-phone'])), 'HOLD_CREATED'],
]) {
  test(`P1.7-truncate: deleting ${name} (and everything after it) from the local journal is detected`, async () => {
    const w = buildV6();
    await act(w);
    const e = lastOf(w, type); assert.ok(e, 'event written: ' + type);
    const v0 = await verifyWorld6(w); assert.equal(v0.ok, true, 'honest journal verifies');
    truncateFrom(w, Number(e.seq));
    const v = await verifyWorld6(w);
    assert.equal(v.ok, false, `truncation of ${type} at seq ${e.seq} went undetected (journal: ${JSON.stringify(v.journal ?? v.v5?.journal)})`.slice(0, 300));
  });
}

test('P1.7-types: the critical types are exactly the security-relevant ones (no rejected-attempt floods)', () => {
  for (const t of ['OWNER_PAYMENT_APPROVAL_VERIFIED', 'FROZEN', 'UNFROZEN', 'HOLD_CREATED', 'HOLD_RELEASED', 'REVOKED', 'INCIDENT_OPENED']) assert.ok(CHECKPOINT_NOW_TYPES.has(t), t);
  for (const t of ['PAYMENT_PROPOSED', 'OWNER_APPROVAL_REJECTED', 'PAYMENT_REJECTED', 'NOTIFICATION_ATTEMPT', 'ATTEMPTS_SUPPRESSED']) assert.ok(!CHECKPOINT_NOW_TYPES.has(t), t);
});
