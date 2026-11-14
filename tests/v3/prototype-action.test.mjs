// Root dispatch regression (independent review PR #28, condition on PR #20): an action type must be an OWN property of
// the version's handler table. Inherited Object.prototype names (toString, constructor, ...) and any function planted on
// Object.prototype must be TRANSITION_TYPE_UNKNOWN and must never advance the sequence, head, used nonces or epoch.
// This file drives V3, V4, V5 and V6 directly so that reverting the lookup in ANY one version fails a test here.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildV3 } from '../../src/v3/world.mjs';
import { applyTransition as applyV3, TR_V } from '../../src/v3/root/chain.mjs';
import { buildV4 } from '../../src/v4/world.mjs';
import { buildV5 } from '../../src/v5/world.mjs';
import { buildV6 } from '../../src/v6/world.mjs';

const INHERITED = ['toString', 'constructor', 'valueOf', 'hasOwnProperty', 'isPrototypeOf', 'propertyIsEnumerable', 'toLocaleString', '__proto__', '__lookupGetter__', '__defineGetter__'];
const PLANTED = 'SBX_PLANTED_HANDLER';
const snap = (s) => JSON.stringify({ seq: s.seq, head: String(s.head), nonces: Object.keys(s.usedNonces ?? {}).sort(), epoch: s.epoch });

async function assertNoAdvance(label, w, submit) {
  Object.defineProperty(Object.prototype, PLANTED, { value: function (s) { if (s && typeof s === 'object' && 'epoch' in s) s.epoch = 99; }, configurable: true, writable: true, enumerable: false });
  try {
    for (const type of [...INHERITED, PLANTED]) {
      const before = snap(w.root.state);
      const r = await submit(type);
      assert.equal(r.ok, false, `${label} ${type} must not commit`);
      assert.equal(r.error?.code, 'TRANSITION_TYPE_UNKNOWN', `${label} ${type}: ${r.error?.code} ${r.error?.detail ?? ''}`);
      assert.equal(snap(w.root.state), before, `${label} ${type} advanced Root state`);
    }
  } finally { delete Object.prototype[PLANTED]; }
}

test('V3 Root: inherited and planted action names are TRANSITION_TYPE_UNKNOWN and do not advance seq/head/nonce/epoch', async () => {
  const w = buildV3();
  await assertNoAdvance('V3', w, (t) => w.submitRaw(t, {}));
});

test('V3 applyTransition directly: an inherited type throws TRANSITION_TYPE_UNKNOWN (no V4/V5 layer in front)', () => {
  const w = buildV3();
  for (const type of ['toString', 'constructor']) {
    const a = w.owner.action(w.view(), type, {});
    const st = w.root.state;
    const tr = { v: TR_V, seq: String(st.seq + 1), prev: st.head, at: a.issuedAt, action: a, approvals: [] };
    assert.throws(() => applyV3(st, tr), (e) => e.code === 'TRANSITION_TYPE_UNKNOWN', type);
  }
});

test('V4 Root: inherited and planted action names (incl. the V3 passthrough table) do not advance state', async () => {
  const w = buildV4();
  await assertNoAdvance('V4', w, (t) => w.submitRaw(t, {}));
});

test('V5 and V6 Root: inherited and planted action names do not advance state; a real handler is still reached', async () => {
  const w5 = buildV5();
  await assertNoAdvance('V5', w5, (t) => w5.submit({ action: w5.action(t, {}) }));
  const w6 = buildV6({ fingerprintOnly: ['k2-laptop'] });
  await assertNoAdvance('V6', w6, (t) => w6.submit({ action: w6.action(t, {}) }));
  const r = await w6.submit({ action: w6.action('HOLD_EXPIRE', { holdId: 'missing' }) });
  assert.equal(r.error?.code, 'HOLD_UNKNOWN');
});
