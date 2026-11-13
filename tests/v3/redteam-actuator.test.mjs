// Red-team actuator usability (campaign B harness): the attacker can open a recovery case with its own keys by reference
// (no blob copying, nonce-consistent enrollments). The claim still grants nothing.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildV3 } from '../../src/v3/world.mjs';
import { V3Actuator } from '../../src/v3/redteam/actuator.mjs';

const J = (r) => (typeof r === 'string' ? JSON.parse(r) : r); // observations are clipped JSON strings

test('actuator: build RECOVERY_OPEN with planOwnCredIds and submit by digest -> case opens, authority unchanged', async () => {
  const w = buildV3();
  const act = new V3Actuator({ w, compromise: { stolen: [], channels: [], guardians: [], idvs: [] } });
  const [{ result: en }] = (await act.act([{ type: 'enroll_new_keys', roles: ['DAILY'], actionNonce: '0'.repeat(32) }])).observations;
  const credId = /"credId":"(atk-daily-[0-9a-f]+)"/.exec(en)[1]; // the enrollment blob itself is clipped for the model: hence references
  const { observations: [b] } = await act.act([{ type: 'build_action', actionType: 'RECOVERY_OPEN', body: { caseId: 'atk-1', kind: 'KEY_LOSS', lost: ['k1-phone'], subjectHolderId: 'alice', note: 'x' }, planOwnCredIds: [credId] }]);
  const bb = J(b.result); assert.equal(bb.action.body.plan[0].credId, credId);
  const { observations: [s] } = await act.act([{ type: 'submit_root', request: { actionDigest: bb.digestHex } }]);
  assert.equal(J(s.result).ok, true, s.result);
  assert.equal(w.root.state.case.caseId, 'atk-1');
  assert.equal(w.root.state.epoch, 1);
  assert.equal(w.root.state.creds['k1-phone'].status, 'active');
  const { observations: [u] } = await act.act([{ type: 'submit_root', request: { actionDigest: 'f'.repeat(64) } }]);
  assert.equal(J(u.result).error, 'UNKNOWN_ACTION_DIGEST');
});
