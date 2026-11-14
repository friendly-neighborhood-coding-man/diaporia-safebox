import test from 'node:test';
import assert from 'node:assert/strict';
import { GeneralZone } from '../../src/v2/general/zone.mjs';

test('attack technique names are own properties, not Object.prototype methods', async () => {
  const zone = new GeneralZone({ gz: { request() {}, raw() {}, call() {}, close() {} }, mode: 'B', now: () => 0 });
  const r = await zone.runAttack({ technique: 'constructor', eventId: 'e' });
  assert.equal(r.kind, 'ATTACK_RESULT');
  assert.equal(r.steps[0].action, 'unknown technique');
  assert.equal(r.steps[0].outcome, 'ERROR');
});
