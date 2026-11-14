// Independent review of the final candidate, F1 (MEDIUM): evidence-free housekeeping transitions (HOLD_EXPIRE,
// RAPID_USE_EXPIRE) looked up request-supplied ids with a bare bracket, so holdId/grantId = 'constructor' found an
// Object.prototype member, passed the existence check and committed a Root transition with no approval.
// Every request-supplied id must be an OWN key; nothing may advance seq, head, used nonces or epoch.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { buildV5 } from '../../src/v5/world.mjs';
import { buildV6 } from '../../src/v6/world.mjs';

const IDS = ['constructor', 'toString', 'valueOf', 'hasOwnProperty', '__proto__', 'isPrototypeOf'];
const full = (s) => createHash('sha256').update(JSON.stringify(s, (k, v) => typeof v === 'bigint' ? 'n' + v : v)).digest('hex');
const snap = (s) => JSON.stringify({ seq: s.seq, head: String(s.head), nonces: Object.keys(s.usedNonces ?? {}).length, epoch: s.epoch, state: full(s) });

for (const [label, build] of [['V5', () => buildV5()], ['V6', () => buildV6({ fingerprintOnly: ['k2-laptop'] })]]) {
  test(`${label}: HOLD_EXPIRE / RAPID_USE_EXPIRE with an inherited id are refused and commit nothing`, async () => {
    const w = build();
    const before = snap(w.root.state); const len0 = w.root.chain(0).length;
    for (const id of IDS) {
      const r1 = await w.submit({ action: w.action('HOLD_EXPIRE', { holdId: id }) });
      assert.equal(r1.ok, false, `HOLD_EXPIRE ${id}`); assert.equal(r1.error.code, 'HOLD_UNKNOWN', `HOLD_EXPIRE ${id}: ${r1.error.code}`);
      const r2 = await w.submit({ action: w.action('RAPID_USE_EXPIRE', { grantId: id }) });
      assert.equal(r2.ok, false, `RAPID_USE_EXPIRE ${id}`); assert.equal(r2.error.code, 'RAPID_GRANT_UNKNOWN', `RAPID_USE_EXPIRE ${id}: ${r2.error.code}`);
    }
    assert.equal(snap(w.root.state), before);
    assert.equal(w.root.chain(0).length, len0);
  });
}
