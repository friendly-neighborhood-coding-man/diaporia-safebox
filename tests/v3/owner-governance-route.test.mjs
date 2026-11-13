// Campaign A thief2 observation (utility): with K1+K4 stolen and ALL guardians + BOTH identity verifiers colluding, the
// recovery protocol cannot complete for the owner (no honest identity or guardian evidence), which is by design (R-3).
// The owner still holds the governance majority (K2 daily + K3 root), so DAILY and FREEZE vacancies are refillable without
// any third party: cancel the open case from a surviving key, revoke the stolen keys, replace the vacancies.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildV3 } from '../../src/v3/world.mjs';
import { ownerOpenCase } from '../../src/v3/recovery/sim.mjs';

const ok = (r, m = '') => { assert.equal(r.ok, true, m + JSON.stringify(r.error)); return r.result; };
const Y = (c) => (BigInt(c) * 10n ** 22n).toString();

test('owner governance route: stolen K1+K4 with all guardians/IDVs colluding -> owner revokes and refills via K2+K3', async () => {
  const w = buildV3();
  ok(await w.ownerAct('SUSPEND', { credId: 'k1-phone' }, ['k2-laptop']));
  ok(await w.ownerAct('SUSPEND', { credId: 'k4-freeze' }, ['k2-laptop']));
  ok((await ownerOpenCase(w, { lost: ['k1-phone', 'k4-freeze'] })).r); // stalls: no honest identity / guardian evidence
  // cancel from a surviving key, then plain governance (no guardians, no identity verifier)
  ok(await w.submitRaw('RECOVERY_CANCEL', { caseId: w.root.state.case.caseId }, { approvals: (a) => w.owner.approvals(a, ['k2-laptop']) }));
  for (const c of ['k1-phone', 'k4-freeze']) ok(await w.ownerAct('REVOKE', { credId: c, reason: 'stolen' }, ['k2-laptop', 'k3-root-hw']), c);
  for (const [old, id, role, ch] of [['k1-phone', 'k1-new', 'DAILY', 'ch-phone'], ['k4-freeze', 'k4-new', 'FREEZE', 'ch-email']]) {
    const nd = w.owner.newDevice({ credId: id, role, holderId: 'alice', channelId: ch, kind: 'passkey' });
    const a = w.owner.action(w.view(), 'REPLACE_VACANT', { revokedCredId: old, newCredential: null });
    a.body.newCredential = nd.enrollment('vault-alice.mock', `vault-alice.mock:${a.nonce}`);
    ok(await w.admin.request('SUBMIT', { request: { action: a, approvals: w.owner.approvals(a, ['k3-root-hw', 'k2-laptop']) } }), id);
    await w.pump();
  }
  ok(await w.pay({ credId: 'k1-new', amountYocto: Y(1) }));
  assert.equal(w.root.state.creds['k1-phone'].status, 'revoked');
  assert.ok(w.root.state.epoch >= 5);
  assert.equal((await w.verify()).takeovers.length, 0);
});
