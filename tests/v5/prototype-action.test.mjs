// Action type names must be own properties of the handler table. Object.prototype
// methods such as toString and constructor are functions, so a bare bracket
// lookup treats them as handlers and the chain commits with no owner approval.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildV5 } from './helpers.mjs';

test('prototype method names do not commit a V5 transition', async () => {
  const w = buildV5();
  const before = { seq: w.root.state.seq, head: w.root.state.head };
  for (const type of ['toString', 'constructor', 'valueOf', '__proto__', 'hasOwnProperty']) {
    const r = await w.submit({ action: w.action(type, {}) });
    assert.equal(r.ok, false, type);
    assert.equal(r.error.code, 'TRANSITION_TYPE_UNKNOWN', type + ' ' + (r.error.detail ?? ''));
  }
  assert.equal(w.root.state.seq, before.seq);
  assert.equal(w.root.state.head, before.head);
});
