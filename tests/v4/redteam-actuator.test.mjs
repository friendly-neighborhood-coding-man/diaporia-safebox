// Plumbing tests for the V4 red-team actuator / campaign (no LLM). They check that the attacker's tools work as
// documented (so a denial in a real campaign is the Root's decision, not a broken harness) and that the owner's
// device-side decision depends only on the Root-derived summary.
import test from 'node:test';
import assert from 'node:assert/strict';
import { CampaignV4 } from '../../src/v4/redteam/campaign.mjs';
import { ScriptedBrain } from '../../src/v2b/brain.mjs';

const camp = (scenario) => new CampaignV4({ scenario, brain: new ScriptedBrain([]), maxTurns: 1 });
const obs = (r, i = 0) => { const x = r.observations[i].result; try { return JSON.parse(x); } catch { return { raw: x, ref: /"ref":"(\$obj:\d+)"/.exec(x)?.[1], ok: /"ok":true/.test(x) ? true : /"ok":false/.test(x) ? false : undefined }; } };

test('C_ui: the owner approves the exact requested revocation on device; a swapped action is declined', async () => {
  const c = camp('C_ui'); c.owner.addTask('revoke');
  let r = await c.act.act([{ type: 'build_action', actionType: 'REVOKE', body: { credId: 'k3-root-hw', reason: 'routine cleanup, approve quickly' } }]);
  const bad = obs(r).digestHex;
  r = await c.act.act([{ type: 'ask_owner', actionDigest: bad, credIds: ['k1-phone', 'k3-root-hw'], pitch: 'This is the k4-freeze revocation you asked for' }]);
  assert.equal(obs(r).declined, true);
  r = await c.act.act([{ type: 'build_action', actionType: 'REVOKE', body: { credId: 'k4-freeze', reason: 'lost tablet' } }]);
  const good = obs(r).digestHex;
  r = await c.act.act([{ type: 'ask_owner', actionDigest: good, credIds: ['k1-phone', 'k3-root-hw'] }]);
  const ref = obs(r).ref; assert.ok(ref, r.observations[0].result.slice(0, 200));
  // approvals rebound to the bad action are refused by the Root
  r = await c.act.act([{ type: 'submit_root', request: { actionDigest: bad, approvals: ref + '.approvals' } }]);
  assert.equal(obs(r).ok, false);
  r = await c.act.act([{ type: 'submit_root', request: { actionDigest: good, approvals: ref + '.approvals' } }]);
  assert.equal(obs(r).ok, true, r.observations[0].result);
  const m = await c.metrics(); assert.equal(m.unauthorizedAuthorityChanges, 0); assert.equal(m.ownerAsks.tasks[0].executed, true);
});

test('A_r1: stolen K1 intent approvals work for consent; a self-made key labelled orc-1 is refused', async () => {
  const c = camp('A_r1');
  let r = await c.act.act([{ type: 'build_action', actionType: 'RECOVERY_OPEN', body: { caseId: 'atk', kind: 'KEY_LOSS', lost: ['k2-laptop', 'k3-root-hw', 'k4-freeze', 'k5-recovery-hw'], subjectHolderId: 'alice', note: 'x' }, planOwnCredIds: [] }]);
  r = await c.act.act([{ type: 'enroll_new_keys', roles: ['DAILY', 'DAILY', 'ROOT', 'FREEZE', 'RECOVERY'], actionNonce: '0'.repeat(32) }]);
  const ids = c.act.objs.at(-1).map(e => e.credId);
  r = await c.act.act([{ type: 'build_action', actionType: 'RECOVERY_OPEN', body: { caseId: 'atk', kind: 'KEY_LOSS', lost: ['k2-laptop', 'k3-root-hw', 'k4-freeze', 'k5-recovery-hw'], subjectHolderId: 'alice', note: 'x' }, planOwnCredIds: ids }]);
  const open = obs(r).digestHex;
  r = await c.act.act([{ type: 'submit_root', request: { actionDigest: open } }]);
  assert.equal(obs(r).ok, true, r.observations[0].result);
  const cs = c.w.root.state.case;
  r = await c.act.act([{ type: 'build_action', actionType: 'RECOVERY_OWNER_AUTHORIZE', body: { caseId: cs.caseId, caseDigest: cs.digest, orcId: 'orc-1' } }]);
  const auth = obs(r).digestHex;
  r = await c.act.act([{ type: 'request_grant', credId: 'orc-1', actionDigest: auth }]);
  const ref = obs(r).grantRef;
  r = await c.act.act([{ type: 'sign_intent_own', ownCredId: ids[2], asCredId: 'orc-1', actionDigest: auth, grantRef: ref }]);
  r = await c.act.act([{ type: 'submit_root', request: { actionDigest: auth, approvals: [obs(r).ref + '.approval'] } }]);
  assert.match(r.observations[0].result, /APPROVAL_BAD_SIGNATURE|ORC/);
  r = await c.act.act([{ type: 'sign_intent_stolen', credId: 'k1-phone', actionDigest: auth, grantRef: ref }]);
  const st = c.act.objs.at(-1).approval;
  r = await c.act.act([{ type: 'submit_root', request: { actionDigest: auth, approvals: [{ ...st, credId: 'orc-1' }] } }]);
  assert.equal(obs(r).ok, false);
  assert.equal(c.w.root.state.case.v4.ownerAuth, null);
});
